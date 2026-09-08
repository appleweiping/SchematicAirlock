"""Offline adapters and lineage checks for physical-verification artifacts.

This module reads bounded, explicitly listed files.  It never invokes Magic,
KLayout, Netgen, a simulator, a shell, or a network client.  The adapters are
small, documented profiles intended for machine-generated reports; ambiguous
input is rejected instead of guessed.
"""

from __future__ import annotations

import json
import math
import re
import unicodedata

# Input is byte/line bounded before parsing, and DTD/entity declarations are rejected.
import xml.etree.ElementTree as ET  # nosec B405
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from hashlib import sha256
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Final

from schematic_airlock._strict_json import MAX_JSON_BYTES, load_strict_json
from schematic_airlock._version import __version__
from schematic_airlock.domain import Decision, InputError, Severity

MAX_ARTIFACTS: Final = 64
MAX_REPORTS: Final = 32
MAX_WAIVERS: Final = 256
MAX_ARTIFACT_BYTES: Final = 64 * 1024 * 1024
MAX_REPORT_BYTES: Final = 2 * 1024 * 1024
MAX_TOTAL_BYTES: Final = 128 * 1024 * 1024
MAX_REPORT_LINES: Final = 20_000
MAX_LINE_CHARACTERS: Final = 8_192
MAX_XML_NODES: Final = 20_000
MAX_XML_DEPTH: Final = 32
MAX_FINDINGS: Final = 20_000
MAX_OBJECTS: Final = 32

_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_RULE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+:-]{0,63}$")
_VARIANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$")
_FINDING_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}-[0-9a-f]{64}$")
_BOX_LINE = re.compile(
    r"^(?:box|bbox)\s*:?\s*"
    r"([^\s,;]+)[\s,]+([^\s,;]+)[\s,;]+"
    r"([^\s,;]+)[\s,]+([^\s,;|]+)"
    r"(?:\s*\|\s*objects\s*=\s*(.+))?$",
    re.IGNORECASE,
)
_KLAYOUT_BOX = re.compile(
    r"box\s*:\s*\(?\s*([^,;()]+)\s*,\s*([^;()]+)\s*;\s*"
    r"([^,;()]+)\s*,\s*([^;()]+)\s*\)?",
    re.IGNORECASE,
)
_NETGEN_UNMATCHED = re.compile(
    r"^(\d+)\s+unmatched\s+(net|nets|device|devices|pin|pins)\s*$", re.IGNORECASE
)
_COUNT_LINE = re.compile(r"^(?:devices|nets)\s*:\s*(\d+)\s*$", re.IGNORECASE)


class VerificationAdapter(StrEnum):
    """The bounded report profiles accepted by the verification gate."""

    MAGIC_DRC = "magic-drc"
    KLAYOUT_DRC = "klayout-drc"
    NETGEN_LVS = "netgen-lvs"
    MAGIC_PEX = "magic-pex"


@dataclass(frozen=True, slots=True)
class ToolIdentity:
    """A report producer named and versioned by the manifest."""

    name: str
    version: str

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "version": self.version}


@dataclass(frozen=True, slots=True)
class VerificationLocation:
    """A report location and optional physical bounding box in micrometres."""

    path: str
    line: int
    column: int = 1
    bbox_um: tuple[float, float, float, float] | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "bbox_um": list(self.bbox_um) if self.bbox_um is not None else None,
        }


@dataclass(frozen=True, slots=True)
class VerificationFinding:
    """One normalized observation from a tool report or lineage gate."""

    severity: Severity
    rule: str
    message: str
    source: str
    tool: ToolIdentity
    location: VerificationLocation | None = None
    objects: tuple[str, ...] = ()
    waived_by: str | None = None

    @property
    def finding_id(self) -> str:
        location = "<none>"
        if self.location is not None:
            bbox = "" if self.location.bbox_um is None else repr(self.location.bbox_um)
            location = f"{self.location.path}:{self.location.line}:{self.location.column}:{bbox}"
        payload = "\0".join(
            (
                self.rule,
                self.source,
                self.tool.name,
                self.tool.version,
                location,
                self.message,
                *self.objects,
            )
        ).encode("utf-8")
        return f"{self.rule}-{sha256(payload).hexdigest()}"

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.finding_id,
            "severity": self.severity.value,
            "rule": self.rule,
            "message": self.message,
            "source": self.source,
            "tool": self.tool.as_dict(),
            "location": self.location.as_dict() if self.location is not None else None,
            "objects": list(self.objects),
            "waived_by": self.waived_by,
        }


@dataclass(frozen=True, slots=True)
class DigestRecord:
    """Content identity of one file read by the verification gate."""

    path: str
    size: int
    sha256: str

    def as_dict(self) -> dict[str, object]:
        return {"path": self.path, "size": self.size, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class VerificationArtifact:
    """A schematic, layout, extracted netlist, or supporting input."""

    artifact_id: str
    kind: str
    digest: DigestRecord

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.artifact_id,
            "kind": self.kind,
            **self.digest.as_dict(),
        }


@dataclass(frozen=True, slots=True)
class VerificationLineage:
    """Content-bound inputs and outputs associated with one tool report."""

    lineage_id: str
    adapter: VerificationAdapter
    tool: ToolIdentity
    report: DigestRecord
    inputs: tuple[VerificationArtifact, ...]
    outputs: tuple[VerificationArtifact, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.lineage_id,
            "adapter": self.adapter.value,
            "tool": self.tool.as_dict(),
            "report": self.report.as_dict(),
            "inputs": [item.as_dict() for item in self.inputs],
            "outputs": [item.as_dict() for item in self.outputs],
        }


@dataclass(frozen=True, slots=True)
class WaiverResult:
    """The deterministic disposition of one exact waiver."""

    waiver_id: str
    status: str
    expires: str
    finding_id: str | None
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.waiver_id,
            "status": self.status,
            "expires": self.expires,
            "finding_id": self.finding_id,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """A strict, deterministic physical-verification lineage report."""

    decision: Decision
    root: str
    assessment_date: str
    evaluated_as_of: str
    manifest_sha256: str
    artifacts: tuple[VerificationArtifact, ...]
    lineage: tuple[VerificationLineage, ...]
    findings: tuple[VerificationFinding, ...]
    waivers: tuple[WaiverResult, ...]
    tool_version: str = __version__

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "tool": {"name": "SchematicAirlock", "version": self.tool_version},
            "decision": self.decision.value,
            "root": self.root,
            "assessment_date": self.assessment_date,
            "evaluated_as_of": self.evaluated_as_of,
            "manifest_sha256": self.manifest_sha256,
            "artifacts": [item.as_dict() for item in self.artifacts],
            "lineage": [item.as_dict() for item in self.lineage],
            "findings": [item.as_dict() for item in self.findings],
            "waivers": [item.as_dict() for item in self.waivers],
        }


@dataclass(frozen=True, slots=True)
class _ArtifactSpec:
    artifact_id: str
    kind: str
    path: str


@dataclass(frozen=True, slots=True)
class _ReportSpec:
    report_id: str
    adapter: VerificationAdapter
    path: str
    tool: ToolIdentity
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _WaiverSpec:
    waiver_id: str
    finding_id: str
    tool: str
    rule: str
    source: str
    line: int | None
    objects: tuple[str, ...]
    expires: date
    reason: str


@dataclass(frozen=True, slots=True)
class _Manifest:
    assessment_date: date
    artifacts: tuple[_ArtifactSpec, ...]
    reports: tuple[_ReportSpec, ...]
    waivers: tuple[_WaiverSpec, ...]


def _exact(value: Mapping[str, object], fields: set[str], context: str) -> None:
    if set(value) != fields:
        raise InputError(f"{context} fields are invalid")


def _text(value: object, context: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise InputError(f"{context} must be a non-empty string of at most {maximum} characters")
    try:
        # Call the base implementation so an adversarial ``str`` subclass
        # cannot replace validation with an arbitrary ``encode`` method.  The
        # decode also returns an exact ``str`` for later hashing and rendering.
        value = str.encode(value, "utf-8", errors="strict").decode("utf-8")
    except UnicodeError as exc:
        raise InputError(f"{context} must contain valid Unicode scalar values") from exc
    if any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for character in value
    ):
        raise InputError(f"{context} contains an unsafe Unicode control or separator")
    return value


def _identifier(value: object, context: str) -> str:
    text = _text(value, context, maximum=64)
    if _IDENTIFIER.fullmatch(text) is None:
        raise InputError(f"{context} is not a portable identifier")
    return text


def _rule_name(value: object, context: str) -> str:
    text = _text(value, context, maximum=128)
    if _RULE.fullmatch(text) is None:
        raise InputError(f"{context} is not a valid rule name")
    return text


def _portable_path(value: object, context: str) -> str:
    text = _text(value, context, maximum=512)
    if unicodedata.normalize("NFC", text) != text:
        raise InputError(f"{context} must use NFC-normalized Unicode")
    path = PurePosixPath(text)
    windows = PureWindowsPath(text)
    parts_are_unsafe = any(
        any(character in '<>:"|?*' for character in part)
        or part.endswith((".", " "))
        or PureWindowsPath(part).is_reserved()
        for part in path.parts
    )
    if (
        "\\" in text
        or path.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or any(part in {"", ".", ".."} for part in path.parts)
        or parts_are_unsafe
        or path.as_posix() != text
    ):
        raise InputError(f"{context} must be a portable bundle-relative path")
    return path.as_posix()


def _mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise InputError(f"{context} must be an object with string keys")
    return value


def _array(value: object, context: str, maximum: int) -> list[object]:
    if not isinstance(value, list) or len(value) > maximum:
        raise InputError(f"{context} must be an array of at most {maximum} items")
    return value


def _identifier_array(value: object, context: str) -> tuple[str, ...]:
    values = tuple(
        _identifier(item, f"{context}[{index}]")
        for index, item in enumerate(_array(value, context, MAX_ARTIFACTS))
    )
    if len({item.casefold() for item in values}) != len(values):
        raise InputError(f"{context} must not contain duplicate identifiers")
    return values


def _objects(value: object, context: str) -> tuple[str, ...]:
    raw = _array(value, context, MAX_OBJECTS)
    values = tuple(sorted((_text(item, context, maximum=128) for item in raw), key=str.casefold))
    if len({item.casefold() for item in values}) != len(values):
        raise InputError(f"{context} must not contain duplicate objects")
    return values


def _parse_date(value: object, context: str) -> date:
    text = _text(value, context, maximum=10)
    try:
        parsed = date.fromisoformat(text)
    except ValueError as exc:
        raise InputError(f"{context} must use YYYY-MM-DD") from exc
    if parsed.isoformat() != text:
        raise InputError(f"{context} must use canonical YYYY-MM-DD")
    return parsed


def _parse_manifest(value: object) -> _Manifest:
    root = _mapping(value, "verification manifest")
    _exact(
        root,
        {"schema_version", "assessment_date", "artifacts", "reports", "waivers"},
        "verification manifest",
    )
    if isinstance(root["schema_version"], bool) or root["schema_version"] != 1:
        raise InputError("verification manifest schema_version must be 1")
    assessment_date = _parse_date(root["assessment_date"], "assessment_date")

    artifacts: list[_ArtifactSpec] = []
    artifact_ids: set[str] = set()
    artifact_paths: set[str] = set()
    role_kinds: set[str] = set()
    for index, item in enumerate(_array(root["artifacts"], "artifacts", MAX_ARTIFACTS)):
        context = f"artifacts[{index}]"
        record = _mapping(item, context)
        _exact(record, {"id", "kind", "path"}, context)
        artifact_id = _identifier(record["id"], f"{context}.id")
        kind = _text(record["kind"], f"{context}.kind", maximum=32)
        if kind not in {"schematic", "layout", "pex", "support"}:
            raise InputError(f"{context}.kind is invalid")
        path = _portable_path(record["path"], f"{context}.path")
        if artifact_id.casefold() in artifact_ids or path.casefold() in artifact_paths:
            raise InputError("artifact IDs and paths must be case-insensitively unique")
        if kind != "support" and kind in role_kinds:
            raise InputError(f"artifact kind {kind!r} is ambiguous")
        artifact_ids.add(artifact_id.casefold())
        artifact_paths.add(path.casefold())
        role_kinds.add(kind)
        artifacts.append(_ArtifactSpec(artifact_id, kind, path))

    expected_tools = {
        VerificationAdapter.MAGIC_DRC: "Magic",
        VerificationAdapter.KLAYOUT_DRC: "KLayout",
        VerificationAdapter.NETGEN_LVS: "Netgen",
        VerificationAdapter.MAGIC_PEX: "Magic",
    }
    reports: list[_ReportSpec] = []
    report_ids: set[str] = set()
    report_paths: set[str] = set()
    producers: dict[str, str] = {}
    known_ids = {item.artifact_id for item in artifacts}
    for index, item in enumerate(_array(root["reports"], "reports", MAX_REPORTS)):
        context = f"reports[{index}]"
        record = _mapping(item, context)
        _exact(record, {"id", "adapter", "path", "tool", "inputs", "outputs"}, context)
        report_id = _identifier(record["id"], f"{context}.id")
        try:
            adapter = VerificationAdapter(
                _text(record["adapter"], f"{context}.adapter", maximum=32)
            )
        except ValueError as exc:
            raise InputError(f"{context}.adapter is invalid") from exc
        path = _portable_path(record["path"], f"{context}.path")
        tool_value = _mapping(record["tool"], f"{context}.tool")
        _exact(tool_value, {"name", "version"}, f"{context}.tool")
        tool_name = _text(tool_value["name"], f"{context}.tool.name", maximum=32)
        version = _text(tool_value["version"], f"{context}.tool.version", maximum=64)
        if tool_name != expected_tools[adapter] or _VERSION.fullmatch(version) is None:
            raise InputError(f"{context}.tool does not match its adapter or has an invalid version")
        inputs = _identifier_array(record["inputs"], f"{context}.inputs")
        outputs = _identifier_array(record["outputs"], f"{context}.outputs")
        if {item.casefold() for item in inputs} & {item.casefold() for item in outputs}:
            raise InputError(f"{context} cannot use one artifact as both input and output")
        for artifact_id in (*inputs, *outputs):
            if artifact_id not in known_ids:
                raise InputError(f"{context} references unknown artifact {artifact_id!r}")
        for artifact_id in outputs:
            key = artifact_id.casefold()
            if key in producers:
                raise InputError(
                    f"artifact {artifact_id!r} has ambiguous producers "
                    f"{producers[key]!r} and {report_id!r}"
                )
            producers[key] = report_id
        if report_id.casefold() in report_ids or path.casefold() in report_paths:
            raise InputError("report IDs and paths must be case-insensitively unique")
        if path.casefold() in artifact_paths:
            raise InputError("artifact and report paths must not overlap")
        report_ids.add(report_id.casefold())
        report_paths.add(path.casefold())
        reports.append(
            _ReportSpec(report_id, adapter, path, ToolIdentity(tool_name, version), inputs, outputs)
        )

    waivers: list[_WaiverSpec] = []
    waiver_ids: set[str] = set()
    for index, item in enumerate(_array(root["waivers"], "waivers", MAX_WAIVERS)):
        context = f"waivers[{index}]"
        record = _mapping(item, context)
        _exact(
            record,
            {
                "id",
                "finding_id",
                "tool",
                "rule",
                "source",
                "line",
                "objects",
                "expires",
                "reason",
            },
            context,
        )
        waiver_id = _identifier(record["id"], f"{context}.id")
        if waiver_id.casefold() in waiver_ids:
            raise InputError("waiver IDs must be case-insensitively unique")
        waiver_ids.add(waiver_id.casefold())
        finding_id = _text(record["finding_id"], f"{context}.finding_id", maximum=193)
        if _FINDING_ID.fullmatch(finding_id) is None:
            raise InputError(f"{context}.finding_id is not a canonical finding identity")
        tool = _text(record["tool"], f"{context}.tool", maximum=32)
        if tool not in set(expected_tools.values()):
            raise InputError(f"{context}.tool is not a supported report producer")
        source = _portable_path(record["source"], f"{context}.source")
        if source not in {item.path for item in reports}:
            raise InputError(f"{context}.source does not name a report")
        line_value = record["line"]
        if line_value is not None and (
            isinstance(line_value, bool)
            or not isinstance(line_value, int)
            or not 1 <= line_value <= MAX_REPORT_LINES
        ):
            raise InputError(f"{context}.line must be null or a bounded positive integer")
        waivers.append(
            _WaiverSpec(
                waiver_id=waiver_id,
                finding_id=finding_id,
                tool=tool,
                rule=_rule_name(record["rule"], f"{context}.rule"),
                source=source,
                line=line_value,
                objects=_objects(record["objects"], f"{context}.objects"),
                expires=_parse_date(record["expires"], f"{context}.expires"),
                reason=_text(record["reason"], f"{context}.reason", maximum=512),
            )
        )
    return _Manifest(assessment_date, tuple(artifacts), tuple(reports), tuple(waivers))


def _bounded_lines(text: str, context: str) -> tuple[str, ...]:
    if not isinstance(text, str):
        raise InputError(f"{context} must be text")
    # One Unicode scalar always needs at least one UTF-8 byte.  Apply this
    # allocation-free lower bound before materialising an encoded copy.
    if len(text) > MAX_REPORT_BYTES:
        raise InputError(f"{context} exceeds the {MAX_REPORT_BYTES} byte limit")
    try:
        encoded_size = len(str.encode(text, "utf-8", errors="strict"))
    except UnicodeError as exc:
        raise InputError(f"{context} must contain valid Unicode scalar values") from exc
    if encoded_size > MAX_REPORT_BYTES:
        raise InputError(f"{context} exceeds the {MAX_REPORT_BYTES} byte limit")
    if "\x00" in text:
        raise InputError(f"{context} contains a NUL byte")
    lines = tuple(text.splitlines())
    if len(lines) > MAX_REPORT_LINES:
        raise InputError(f"{context} exceeds the line-count limit")
    if any(len(line) > MAX_LINE_CHARACTERS for line in lines):
        raise InputError(f"{context} contains an oversized line")
    return lines


def _finite_number(token: str, context: str) -> float:
    cleaned = token.strip().lower()
    if cleaned.endswith("um"):
        cleaned = cleaned[:-2]
    if len(cleaned) > 48:
        raise InputError(f"{context} contains an oversized number")
    try:
        value = Decimal(cleaned)
    except InvalidOperation as exc:
        raise InputError(f"{context} contains an invalid coordinate") from exc
    if not value.is_finite() or value.adjusted() > 12 or value.adjusted() < -12:
        raise InputError(f"{context} contains a non-finite or out-of-range coordinate")
    result = float(value)
    if not math.isfinite(result):
        raise InputError(f"{context} contains a non-finite coordinate")
    return 0.0 if result == 0 else result


def _parse_object_text(value: str, context: str) -> tuple[str, ...]:
    if not value.strip():
        return ()
    return _objects([item.strip() for item in value.split(",")], context)


def _report_identity(name: str, version: str, source: str) -> tuple[ToolIdentity, str]:
    checked_version = _text(version, f"{name} version", maximum=64)
    if _VERSION.fullmatch(checked_version) is None:
        raise InputError(f"{name} version is invalid")
    return ToolIdentity(name, checked_version), _portable_path(source, f"{name} report source")


def _finding(
    *,
    severity: Severity,
    rule: str,
    message: str,
    source: str,
    tool: ToolIdentity,
    line: int | None = None,
    bbox_um: tuple[float, float, float, float] | None = None,
    objects: tuple[str, ...] = (),
) -> VerificationFinding:
    return VerificationFinding(
        severity=severity,
        rule=_rule_name(rule, "normalized finding rule"),
        message=_text(message, "normalized finding message", maximum=2_048),
        source=_portable_path(source, "normalized finding source"),
        tool=tool,
        location=(
            VerificationLocation(source, line, bbox_um=bbox_um) if line is not None else None
        ),
        objects=objects,
    )


def parse_magic_drc(
    text: str, *, source: str, tool_version: str
) -> tuple[VerificationFinding, ...]:
    """Parse the strict Magic DRC text profile documented by this project."""

    lines = _bounded_lines(text, "Magic DRC report")
    tool, source = _report_identity("Magic", tool_version, source)
    clean_markers = {"no drc errors found.", "total drc errors: 0"}
    meaningful = [(index, line.strip()) for index, line in enumerate(lines, 1) if line.strip()]
    if not meaningful:
        raise InputError("Magic DRC report is empty")
    clean_count = sum(line.casefold() in clean_markers for _, line in meaningful)
    if clean_count:
        if clean_count != 1:
            raise InputError("Magic DRC report repeats its clean terminal result")
        if sum(line.lower().startswith("cell:") for _, line in meaningful) > 1:
            raise InputError("Magic DRC report contains an ambiguous cell record")
        allowed = clean_markers | {
            line.casefold() for _, line in meaningful if line.lower().startswith("cell:")
        }
        if any(line.casefold() not in allowed for _, line in meaningful):
            raise InputError("Magic DRC report mixes a clean result with violation data")
        for _, line in meaningful:
            if line.lower().startswith("cell:"):
                _text(line.split(":", 1)[1].strip(), "Magic DRC cell", maximum=128)
        return ()

    cell = ""
    current_rule: str | None = None
    current_message: str | None = None
    current_rule_line: int | None = None
    current_boxes = 0
    findings: list[VerificationFinding] = []
    for line_number, value in meaningful:
        if value.lower().startswith("cell:"):
            if current_rule is not None or cell:
                raise InputError("Magic DRC report contains an ambiguous cell record")
            cell = _text(value.split(":", 1)[1].strip(), "Magic DRC cell", maximum=128)
            continue
        if value.lower().startswith("rule:"):
            if current_rule is not None and current_boxes == 0:
                findings.append(
                    _finding(
                        severity=Severity.DENY,
                        rule=current_rule,
                        message=current_message or "Magic reported a DRC violation",
                        source=source,
                        tool=tool,
                        line=current_rule_line,
                        objects=(cell,) if cell else (),
                    )
                )
            payload = value.split(":", 1)[1].strip()
            if "|" not in payload:
                raise InputError("Magic DRC Rule records require 'RULE | message'")
            rule, message = (part.strip() for part in payload.split("|", 1))
            current_rule = _rule_name(rule, "Magic DRC rule")
            current_message = _text(message, "Magic DRC message", maximum=2_048)
            current_rule_line = line_number
            current_boxes = 0
            continue
        box = _BOX_LINE.fullmatch(value)
        if box is not None:
            if current_rule is None or current_message is None:
                raise InputError("Magic DRC Box record appears before a Rule record")
            bbox = (
                _finite_number(box.group(1), "Magic DRC box"),
                _finite_number(box.group(2), "Magic DRC box"),
                _finite_number(box.group(3), "Magic DRC box"),
                _finite_number(box.group(4), "Magic DRC box"),
            )
            if bbox[0] > bbox[2] or bbox[1] > bbox[3]:
                raise InputError("Magic DRC box coordinates are reversed")
            explicit_objects = _parse_object_text(box.group(5) or "", "Magic DRC objects")
            objects = explicit_objects or ((cell,) if cell else ())
            findings.append(
                _finding(
                    severity=Severity.DENY,
                    rule=current_rule,
                    message=current_message,
                    source=source,
                    tool=tool,
                    line=line_number,
                    bbox_um=bbox,
                    objects=objects,
                )
            )
            current_boxes += 1
            if len(findings) > MAX_FINDINGS:
                raise InputError("Magic DRC report exceeds the finding limit")
            continue
        raise InputError(f"Magic DRC report has an ambiguous record at line {line_number}")
    if current_rule is not None and current_boxes == 0:
        findings.append(
            _finding(
                severity=Severity.DENY,
                rule=current_rule,
                message=current_message or "Magic reported a DRC violation",
                source=source,
                tool=tool,
                line=current_rule_line,
                objects=(cell,) if cell else (),
            )
        )
    if not findings:
        raise InputError("Magic DRC report contains no result")
    return tuple(findings)


def _xml_children_text(parent: ET.Element, tag: str, context: str) -> str:
    children = [child for child in parent if child.tag == tag]
    if len(children) != 1 or children[0].text is None or len(children[0]):
        raise InputError(f"{context} requires exactly one {tag!r} element")
    return _text(children[0].text.strip(), f"{context}.{tag}", maximum=2_048)


def _xml_reject_mixed_text(parent: ET.Element, context: str) -> None:
    if parent.text is not None and parent.text.strip():
        raise InputError(f"{context} contains unexpected mixed text")
    if any(child.tail is not None and child.tail.strip() for child in parent):
        raise InputError(f"{context} contains unexpected mixed text")


def _xml_require_leaf(element: ET.Element, context: str) -> None:
    if len(element):
        raise InputError(f"{context} must not contain nested elements")


def _xml_shape(
    parent: ET.Element,
    *,
    required: set[str],
    optional: set[str],
    context: str,
) -> None:
    _xml_reject_mixed_text(parent, context)
    tags = [child.tag for child in parent]
    allowed = required | optional
    if any(not isinstance(tag, str) or tag not in allowed for tag in tags):
        raise InputError(f"{context} contains an unknown field")
    for tag in required:
        if tags.count(tag) != 1:
            raise InputError(f"{context} requires exactly one {tag!r} element")
    for tag in optional:
        if tags.count(tag) > 1:
            raise InputError(f"{context} repeats optional field {tag!r}")
    if len(tags) != len(set(tags)):
        raise InputError(f"{context} contains a duplicate field")


def _klayout_category_reference(value: str, context: str) -> str:
    reference = value.strip()
    if len(reference) >= 2 and reference[0] in {"'", '"'}:
        if reference[-1] != reference[0] or reference[0] in reference[1:-1]:
            raise InputError(f"{context} has an ambiguous quoted category path")
        reference = reference[1:-1]
    if "." in reference and not value.strip().startswith(("'", '"')):
        raise InputError(f"{context} must quote a category name containing a dot")
    return _rule_name(reference, context)


def parse_klayout_drc(
    text: str, *, source: str, tool_version: str
) -> tuple[VerificationFinding, ...]:
    """Parse a bounded KLayout report-database XML document."""

    _bounded_lines(text, "KLayout DRC report")
    lowered = text.casefold()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise InputError("KLayout DRC XML must not contain DTD or entity declarations")
    try:
        root = ET.fromstring(text)  # nosec B314
    except ET.ParseError as exc:
        raise InputError(f"invalid KLayout DRC XML: {exc}") from exc
    if root.tag != "report-database":
        raise InputError("KLayout DRC XML root must be 'report-database'")
    pending: list[tuple[ET.Element, int]] = [(root, 0)]
    count = 0
    while pending:
        element, depth = pending.pop()
        count += 1
        if count > MAX_XML_NODES or depth > MAX_XML_DEPTH:
            raise InputError("KLayout DRC XML exceeds complexity limits")
        if element.attrib:
            raise InputError("KLayout DRC XML attributes are not accepted by this profile")
        pending.extend((child, depth + 1) for child in element)

    _xml_shape(
        root,
        required={"categories", "cells", "items"},
        optional={"description", "original-file", "generator", "top-cell", "tags"},
        context="KLayout report database",
    )
    root_children = list(root)
    categories_parent = next(child for child in root_children if child.tag == "categories")
    cells_parent = next(child for child in root_children if child.tag == "cells")
    items_parent = next(child for child in root_children if child.tag == "items")
    _xml_reject_mixed_text(categories_parent, "KLayout categories")
    _xml_reject_mixed_text(cells_parent, "KLayout cells")
    _xml_reject_mixed_text(items_parent, "KLayout items")
    for child in root_children:
        if child.tag not in {"categories", "cells", "items"}:
            _xml_require_leaf(child, f"KLayout report database.{child.tag}")
    categories: dict[str, tuple[str, str]] = {}
    category_keys: set[str] = set()
    if any(child.tag != "category" for child in categories_parent):
        raise InputError("KLayout categories contains an unknown field")
    for index, category in enumerate(categories_parent):
        context = f"KLayout category[{index}]"
        _xml_shape(
            category,
            required={"name"},
            optional={"description"},
            context=context,
        )
        name = _rule_name(_xml_children_text(category, "name", context), f"{context}.name")
        description_children = [child for child in category if child.tag == "description"]
        description = name
        if description_children:
            _xml_require_leaf(description_children[0], f"{context}.description")
        if description_children and description_children[0].text:
            description = _text(
                description_children[0].text.strip(), f"{context}.description", maximum=2_048
            )
        if name.casefold() in category_keys:
            raise InputError("KLayout DRC category names must be case-insensitively unique")
        category_keys.add(name.casefold())
        categories[name] = (name, description)
    cells: dict[str, str] = {}
    cell_keys: set[str] = set()
    if any(child.tag != "cell" for child in cells_parent):
        raise InputError("KLayout cells contains an unknown field")
    for index, cell in enumerate(cells_parent):
        context = f"KLayout cell[{index}]"
        _xml_shape(
            cell,
            required={"name"},
            optional={"variant", "layout-name"},
            context=context,
        )
        for child in cell:
            _xml_require_leaf(child, f"{context}.{child.tag}")
        name = _xml_children_text(cell, "name", context)
        variants = [child for child in cell if child.tag == "variant"]
        variant = ""
        if variants:
            variant = _xml_children_text(cell, "variant", context)
            if _VARIANT.fullmatch(variant) is None:
                raise InputError(f"{context}.variant is not a portable variant identifier")
        qualified_name = f"{name}:{variant}" if variant else name
        if qualified_name.casefold() in cell_keys:
            raise InputError("KLayout DRC cell names must be case-insensitively unique")
        cell_keys.add(qualified_name.casefold())
        cells[qualified_name] = name

    findings: list[VerificationFinding] = []
    tool, source = _report_identity("KLayout", tool_version, source)
    item_lines = [
        line_number
        for line_number, line in enumerate(text.splitlines(), 1)
        if re.search(r"<item(?:\s|>)", line) is not None
    ]
    items = items_parent.findall("item")
    if len(items) != len(list(items_parent)):
        raise InputError("KLayout items contains an unknown field")
    if len(item_lines) != len(items):
        raise InputError("KLayout DRC items must each start on a distinct report line")
    for index, item in enumerate(items, 1):
        context = f"KLayout item[{index - 1}]"
        _xml_shape(
            item,
            required={"category", "cell", "values"},
            optional={"tags", "visited", "multiplicity", "comment", "image"},
            context=context,
        )
        category_name = _klayout_category_reference(
            _xml_children_text(item, "category", context), f"{context}.category"
        )
        cell_name = _xml_children_text(item, "cell", context)
        if category_name not in categories or cell_name not in cells:
            raise InputError(f"{context} references an unknown category or cell")
        values = item.find("values")
        if values is None:
            raise InputError(f"{context} requires values")
        if any(child.tag != "value" for child in values):
            raise InputError(f"{context}.values contains an unknown field")
        _xml_reject_mixed_text(values, f"{context}.values")
        for child in values:
            _xml_require_leaf(child, f"{context}.values.value")
        for child in item:
            if child.tag != "values":
                _xml_require_leaf(child, f"{context}.{child.tag}")
        value_texts = [
            child.text.strip()
            for child in values.findall("value")
            if child.text is not None and child.text.strip()
        ]
        if not value_texts:
            raise InputError(f"{context} requires a non-empty value")
        bbox: tuple[float, float, float, float] | None = None
        for value_text in value_texts:
            match = _KLAYOUT_BOX.search(value_text)
            if match is None:
                continue
            candidate = (
                _finite_number(match.group(1), context),
                _finite_number(match.group(2), context),
                _finite_number(match.group(3), context),
                _finite_number(match.group(4), context),
            )
            if bbox is not None:
                raise InputError(f"{context} contains ambiguous multiple boxes")
            if candidate[0] > candidate[2] or candidate[1] > candidate[3]:
                raise InputError(f"{context} contains reversed box coordinates")
            bbox = candidate
        rule, message = categories[category_name]
        findings.append(
            _finding(
                severity=Severity.DENY,
                rule=rule,
                message=message,
                source=source,
                tool=tool,
                line=item_lines[index - 1],
                bbox_um=bbox,
                objects=(cells[cell_name],),
            )
        )
        if len(findings) > MAX_FINDINGS:
            raise InputError("KLayout DRC report exceeds the finding limit")
    return tuple(findings)


def parse_netgen_lvs(
    text: str, *, source: str, tool_version: str
) -> tuple[VerificationFinding, ...]:
    """Parse terminal results and mismatch summaries from a Netgen LVS report."""

    lines = _bounded_lines(text, "Netgen LVS report")
    tool, source = _report_identity("Netgen", tool_version, source)
    findings: list[VerificationFinding] = []
    matched = False
    mismatched = False
    for line_number, raw in enumerate(lines, 1):
        value = raw.strip()
        folded = value.casefold()
        if not value or set(value) <= {"-", "="}:
            continue
        if folded in {
            "circuits match uniquely.",
            "netlists match uniquely.",
            "result: circuits match uniquely.",
            "result: netlists match uniquely.",
            "lvs result: match",
        }:
            matched = True
            continue
        if folded in {
            "netlists do not match.",
            "circuits do not match.",
            "result: netlists do not match.",
            "result: circuits do not match.",
            "lvs result: mismatch",
        }:
            mismatched = True
            findings.append(
                _finding(
                    severity=Severity.DENY,
                    rule="LVS.MISMATCH",
                    message="The schematic and layout netlists do not match",
                    source=source,
                    tool=tool,
                    line=line_number,
                )
            )
            continue
        if folded == "property errors were found.":
            mismatched = True
            findings.append(
                _finding(
                    severity=Severity.DENY,
                    rule="LVS.PROPERTY",
                    message="Netgen reported device-property mismatches",
                    source=source,
                    tool=tool,
                    line=line_number,
                )
            )
            continue
        count_match = _NETGEN_UNMATCHED.match(value)
        if count_match is not None:
            count = int(count_match.group(1))
            if count > 1_000_000:
                raise InputError("Netgen LVS mismatch count exceeds the supported limit")
            if count:
                mismatched = True
                family = count_match.group(2).lower().rstrip("s")
                findings.append(
                    _finding(
                        severity=Severity.DENY,
                        rule=f"LVS.UNMATCHED_{family.upper()}",
                        message=f"Netgen reported {count} unmatched {family}(s)",
                        source=source,
                        tool=tool,
                        line=line_number,
                    )
                )
            continue
        if folded.startswith("warning:"):
            findings.append(
                _finding(
                    severity=Severity.REVIEW,
                    rule="LVS.WARNING",
                    message=_text(value.split(":", 1)[1].strip(), "Netgen warning"),
                    source=source,
                    tool=tool,
                    line=line_number,
                )
            )
            continue
        if folded.startswith("error:"):
            mismatched = True
            findings.append(
                _finding(
                    severity=Severity.DENY,
                    rule="LVS.ERROR",
                    message=_text(value.split(":", 1)[1].strip(), "Netgen error"),
                    source=source,
                    tool=tool,
                    line=line_number,
                )
            )
            continue
        if folded == "lvs done" or folded.startswith(
            ("circuit 1:", "circuit 2:", "subcircuit summary:")
        ):
            continue
        raise InputError(f"Netgen LVS report has an ambiguous record at line {line_number}")
    if matched and mismatched:
        raise InputError("Netgen LVS report contains conflicting terminal results")
    if not matched and not mismatched:
        raise InputError("Netgen LVS report has no recognized terminal result")
    if len(findings) > MAX_FINDINGS:
        raise InputError("Netgen LVS report exceeds the finding limit")
    return tuple(findings)


def parse_magic_pex(
    text: str, *, source: str, tool_version: str
) -> tuple[VerificationFinding, ...]:
    """Parse the bounded completion/warning/error profile for Magic PEX logs."""

    lines = _bounded_lines(text, "Magic PEX report")
    tool, source = _report_identity("Magic", tool_version, source)
    findings: list[VerificationFinding] = []
    complete = False
    failed = False
    output: str | None = None
    for line_number, raw in enumerate(lines, 1):
        value = raw.strip()
        folded = value.casefold()
        if not value:
            continue
        if folded in {"pex status: complete", "extraction complete."}:
            complete = True
            continue
        if folded.startswith("output:"):
            if output is not None:
                raise InputError("Magic PEX report contains duplicate Output records")
            output = _portable_path(value.split(":", 1)[1].strip(), "Magic PEX output")
            continue
        count = _COUNT_LINE.fullmatch(value)
        if count is not None:
            if int(count.group(1)) > 10_000_000:
                raise InputError("Magic PEX count exceeds the supported limit")
            continue
        if folded.startswith("warning:"):
            findings.append(
                _finding(
                    severity=Severity.REVIEW,
                    rule="PEX.WARNING",
                    message=_text(value.split(":", 1)[1].strip(), "Magic PEX warning"),
                    source=source,
                    tool=tool,
                    line=line_number,
                )
            )
            continue
        if folded.startswith("error:"):
            failed = True
            findings.append(
                _finding(
                    severity=Severity.DENY,
                    rule="PEX.ERROR",
                    message=_text(value.split(":", 1)[1].strip(), "Magic PEX error"),
                    source=source,
                    tool=tool,
                    line=line_number,
                )
            )
            continue
        raise InputError(f"Magic PEX report has an ambiguous record at line {line_number}")
    if complete and failed:
        raise InputError("Magic PEX report contains conflicting terminal results")
    if not complete and not failed:
        raise InputError("Magic PEX report has no recognized terminal result")
    if complete and output is None:
        raise InputError("completed Magic PEX report has no Output record")
    return tuple(findings)


def _magic_pex_output(text: str) -> str | None:
    outputs = [
        line.split(":", 1)[1].strip()
        for line in _bounded_lines(text, "Magic PEX report")
        if line.strip().casefold().startswith("output:")
    ]
    if len(outputs) > 1:
        raise InputError("Magic PEX report contains duplicate Output records")
    return _portable_path(outputs[0], "Magic PEX output") if outputs else None


_PARSERS: Mapping[
    VerificationAdapter,
    Callable[..., tuple[VerificationFinding, ...]],
] = {
    VerificationAdapter.MAGIC_DRC: parse_magic_drc,
    VerificationAdapter.KLAYOUT_DRC: parse_klayout_drc,
    VerificationAdapter.NETGEN_LVS: parse_netgen_lvs,
    VerificationAdapter.MAGIC_PEX: parse_magic_pex,
}


def _safe_file(root: Path, relative: str, context: str) -> Path:
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise InputError(f"{context} escapes the verification bundle or does not exist") from exc
    if not resolved.is_file():
        raise InputError(f"{context} is not a regular file")
    return resolved


def _claim_file(path: Path, claimed: list[Path]) -> None:
    try:
        duplicate = any(path.samefile(other) for other in claimed)
    except OSError as exc:
        raise InputError(f"cannot identify verification bundle file {path}") from exc
    if duplicate:
        raise InputError("manifest paths resolve to the same physical file")
    claimed.append(path)


def _read_and_digest(
    root: Path,
    relative: str,
    context: str,
    maximum: int,
) -> tuple[DigestRecord, bytes]:
    path = _safe_file(root, relative, context)
    try:
        size = path.stat().st_size
        if size > maximum:
            raise InputError(f"{context} exceeds the {maximum} byte limit")
        with path.open("rb") as stream:
            payload = stream.read(maximum + 1)
    except OSError as exc:
        raise InputError(f"cannot read {context}: {exc}") from exc
    if len(payload) > maximum or len(payload) != size:
        raise InputError(f"{context} changed while it was being read or exceeds its limit")
    return DigestRecord(relative, size, sha256(payload).hexdigest()), payload


def _decode_report(payload: bytes, context: str) -> str:
    try:
        return payload.decode("utf-8")
    except UnicodeError as exc:
        raise InputError(f"{context} must be UTF-8") from exc


def _lineage_findings(
    manifest_source: str,
    manifest: _Manifest,
    artifacts: Mapping[str, VerificationArtifact],
) -> list[VerificationFinding]:
    gate = ToolIdentity("SchematicAirlock", __version__)
    findings: list[VerificationFinding] = []
    roles = {artifact.kind: artifact.artifact_id for artifact in artifacts.values()}
    for role in ("schematic", "layout", "pex"):
        if role not in roles:
            findings.append(
                _finding(
                    severity=Severity.DENY,
                    rule="LINEAGE.MISSING_VIEW",
                    message=f"The verification bundle has no {role} artifact",
                    source=manifest_source,
                    tool=gate,
                    objects=(role,),
                )
            )

    expected: Mapping[VerificationAdapter, tuple[set[str], set[str]]] = {
        VerificationAdapter.MAGIC_DRC: ({"layout"}, set()),
        VerificationAdapter.KLAYOUT_DRC: ({"layout"}, set()),
        VerificationAdapter.NETGEN_LVS: ({"schematic", "layout"}, set()),
        VerificationAdapter.MAGIC_PEX: ({"layout"}, {"pex"}),
    }
    valid_adapters: set[VerificationAdapter] = set()
    for report in manifest.reports:
        input_kinds = {artifacts[item.casefold()].kind for item in report.inputs}
        output_kinds = {artifacts[item.casefold()].kind for item in report.outputs}
        wanted_inputs, wanted_outputs = expected[report.adapter]
        if input_kinds != wanted_inputs or output_kinds != wanted_outputs:
            findings.append(
                _finding(
                    severity=Severity.DENY,
                    rule="LINEAGE.ADAPTER_CONTRACT",
                    message=(
                        f"{report.adapter.value} must bind inputs {sorted(wanted_inputs)} "
                        f"and outputs {sorted(wanted_outputs)}"
                    ),
                    source=manifest_source,
                    tool=gate,
                    objects=(report.report_id,),
                )
            )
        else:
            valid_adapters.add(report.adapter)
    if not valid_adapters & {
        VerificationAdapter.MAGIC_DRC,
        VerificationAdapter.KLAYOUT_DRC,
    }:
        findings.append(
            _finding(
                severity=Severity.DENY,
                rule="LINEAGE.MISSING_DRC",
                message="No valid layout DRC lineage is present",
                source=manifest_source,
                tool=gate,
                objects=("layout",),
            )
        )
    if VerificationAdapter.NETGEN_LVS not in valid_adapters:
        findings.append(
            _finding(
                severity=Severity.DENY,
                rule="LINEAGE.MISSING_LVS",
                message="No valid schematic-to-layout LVS lineage is present",
                source=manifest_source,
                tool=gate,
                objects=("schematic", "layout"),
            )
        )
    if VerificationAdapter.MAGIC_PEX not in valid_adapters:
        findings.append(
            _finding(
                severity=Severity.DENY,
                rule="LINEAGE.MISSING_PEX",
                message="No valid layout-to-PEX lineage is present",
                source=manifest_source,
                tool=gate,
                objects=("layout", "pex"),
            )
        )
    return findings


def _matches(waiver: _WaiverSpec, finding: VerificationFinding) -> bool:
    line = finding.location.line if finding.location is not None else None
    return (
        finding.finding_id == waiver.finding_id
        and finding.tool.name.casefold() == waiver.tool.casefold()
        and finding.rule == waiver.rule
        and finding.source == waiver.source
        and (waiver.line is None or line == waiver.line)
        and finding.objects == waiver.objects
    )


def _apply_waivers(
    findings: Sequence[VerificationFinding],
    waivers: Sequence[_WaiverSpec],
    assessment_date: date,
    manifest_source: str,
) -> tuple[list[VerificationFinding], list[WaiverResult]]:
    updated = list(findings)
    results: list[WaiverResult] = []
    matched_by: dict[int, str] = {}
    gate = ToolIdentity("SchematicAirlock", __version__)
    notices: list[VerificationFinding] = []
    for waiver in waivers:
        matches = [index for index, finding in enumerate(updated) if _matches(waiver, finding)]
        if len(matches) > 1:
            raise InputError(f"waiver {waiver.waiver_id!r} ambiguously matches multiple findings")
        finding_id = updated[matches[0]].finding_id if matches else None
        if matches:
            index = matches[0]
            if index in matched_by:
                raise InputError(
                    f"waivers {matched_by[index]!r} and {waiver.waiver_id!r} "
                    "ambiguously match one finding"
                )
            matched_by[index] = waiver.waiver_id
        if waiver.expires < assessment_date:
            results.append(
                WaiverResult(
                    waiver.waiver_id,
                    "expired",
                    waiver.expires.isoformat(),
                    finding_id,
                    waiver.reason,
                )
            )
            notices.append(
                _finding(
                    severity=Severity.REVIEW,
                    rule="WAIVER.EXPIRED",
                    message=(
                        f"Waiver {waiver.waiver_id!r} expired on {waiver.expires.isoformat()}"
                    ),
                    source=manifest_source,
                    tool=gate,
                    objects=(waiver.waiver_id,),
                )
            )
            continue
        if not matches:
            results.append(
                WaiverResult(
                    waiver.waiver_id,
                    "unused",
                    waiver.expires.isoformat(),
                    None,
                    waiver.reason,
                )
            )
            notices.append(
                _finding(
                    severity=Severity.REVIEW,
                    rule="WAIVER.UNUSED",
                    message=f"Waiver {waiver.waiver_id!r} did not match any finding",
                    source=manifest_source,
                    tool=gate,
                    objects=(waiver.waiver_id,),
                )
            )
            continue
        index = matches[0]
        updated[index] = replace(updated[index], waived_by=waiver.waiver_id)
        results.append(
            WaiverResult(
                waiver.waiver_id,
                "applied",
                waiver.expires.isoformat(),
                updated[index].finding_id,
                waiver.reason,
            )
        )
    return updated + notices, results


def _decision(findings: Sequence[VerificationFinding]) -> Decision:
    rank = max(
        (finding.severity.rank for finding in findings if finding.waived_by is None),
        default=0,
    )
    return (Decision.ALLOW, Decision.REVIEW, Decision.DENY)[rank]


def verify_path(path: str | Path, *, as_of: date | None = None) -> VerificationReport:
    """Verify one offline lineage bundle as of a trusted date.

    The default is the current UTC date.  ``as_of`` exists for explicit,
    reproducible historical evaluation by API callers; it is never read from
    the untrusted manifest and the CLI deliberately does not expose an
    override.
    """

    if as_of is None:
        evaluated_as_of = datetime.now(UTC).date()
    elif type(as_of) is date:
        evaluated_as_of = as_of
    else:
        raise InputError("as_of must be a datetime.date")

    candidate = Path(path)
    if candidate.is_dir():
        manifest_path = candidate / "verification.json"
        root = candidate.resolve(strict=True)
        manifest_source = "verification.json"
    else:
        manifest_path = candidate
        try:
            root = candidate.parent.resolve(strict=True)
        except OSError as exc:
            raise InputError(
                f"verification manifest parent does not exist: {candidate.parent}"
            ) from exc
        manifest_source = candidate.name
    if not manifest_path.exists() or not manifest_path.is_file():
        raise InputError(f"verification manifest does not exist: {manifest_path}")
    manifest_relative = _portable_path(manifest_source, "verification manifest path")
    manifest_digest, manifest_payload = _read_and_digest(
        root, manifest_relative, "verification manifest", MAX_JSON_BYTES
    )
    try:
        manifest_text = manifest_payload.decode("utf-8")
    except UnicodeError as exc:
        raise InputError("verification manifest must be UTF-8") from exc
    manifest = _parse_manifest(load_strict_json(manifest_text, context="verification manifest"))
    if manifest.assessment_date > evaluated_as_of:
        raise InputError("assessment_date must not be later than the evaluation date")

    artifacts_by_key: dict[str, VerificationArtifact] = {}
    resolved_files = [manifest_path.resolve(strict=True)]
    total_bytes = len(manifest_payload)
    for artifact_spec in manifest.artifacts:
        resolved = _safe_file(root, artifact_spec.path, f"artifact {artifact_spec.artifact_id!r}")
        _claim_file(resolved, resolved_files)
        digest, _ = _read_and_digest(
            root,
            artifact_spec.path,
            f"artifact {artifact_spec.artifact_id!r}",
            MAX_ARTIFACT_BYTES,
        )
        total_bytes += digest.size
        if total_bytes > MAX_TOTAL_BYTES:
            raise InputError("verification bundle exceeds the total byte limit")
        artifacts_by_key[artifact_spec.artifact_id.casefold()] = VerificationArtifact(
            artifact_spec.artifact_id, artifact_spec.kind, digest
        )

    lineage: list[VerificationLineage] = []
    adapter_findings: list[VerificationFinding] = []
    integrity_findings: list[VerificationFinding] = []
    gate = ToolIdentity("SchematicAirlock", __version__)
    for report_spec in manifest.reports:
        resolved = _safe_file(root, report_spec.path, f"report {report_spec.report_id!r}")
        _claim_file(resolved, resolved_files)
        digest, payload = _read_and_digest(
            root,
            report_spec.path,
            f"report {report_spec.report_id!r}",
            MAX_REPORT_BYTES,
        )
        total_bytes += digest.size
        if total_bytes > MAX_TOTAL_BYTES:
            raise InputError("verification bundle exceeds the total byte limit")
        parser = _PARSERS[report_spec.adapter]
        report_text = _decode_report(payload, f"report {report_spec.report_id!r}")
        adapter_findings.extend(
            parser(
                report_text,
                source=report_spec.path,
                tool_version=report_spec.tool.version,
            )
        )
        if report_spec.adapter is VerificationAdapter.MAGIC_PEX:
            reported_output = _magic_pex_output(report_text)
            expected_outputs = [
                artifacts_by_key[item.casefold()].digest.path for item in report_spec.outputs
            ]
            if len(expected_outputs) == 1 and reported_output != expected_outputs[0]:
                integrity_findings.append(
                    _finding(
                        severity=Severity.DENY,
                        rule="LINEAGE.PEX_OUTPUT_MISMATCH",
                        message="Magic PEX output does not match its declared artifact",
                        source=report_spec.path,
                        tool=gate,
                        objects=tuple(expected_outputs),
                    )
                )
        lineage.append(
            VerificationLineage(
                lineage_id=report_spec.report_id,
                adapter=report_spec.adapter,
                tool=report_spec.tool,
                report=digest,
                inputs=tuple(artifacts_by_key[item.casefold()] for item in report_spec.inputs),
                outputs=tuple(artifacts_by_key[item.casefold()] for item in report_spec.outputs),
            )
        )
    if len(adapter_findings) > MAX_FINDINGS:
        raise InputError("verification bundle exceeds the finding limit")

    waived_findings, waiver_results = _apply_waivers(
        adapter_findings,
        manifest.waivers,
        evaluated_as_of,
        manifest_source,
    )
    all_findings = (
        waived_findings
        + integrity_findings
        + _lineage_findings(manifest_source, manifest, artifacts_by_key)
    )
    if len(all_findings) > MAX_FINDINGS:
        raise InputError("verification bundle exceeds the total finding limit")
    all_findings.sort(
        key=lambda finding: (
            finding.source.casefold(),
            finding.location.line if finding.location is not None else 0,
            finding.rule,
            finding.finding_id,
        )
    )
    artifacts = tuple(
        sorted(artifacts_by_key.values(), key=lambda item: item.artifact_id.casefold())
    )
    lineage.sort(key=lambda item: item.lineage_id.casefold())
    waiver_results.sort(key=lambda item: item.waiver_id.casefold())
    return VerificationReport(
        decision=_decision(all_findings),
        root=".",
        assessment_date=manifest.assessment_date.isoformat(),
        evaluated_as_of=evaluated_as_of.isoformat(),
        manifest_sha256=manifest_digest.sha256,
        artifacts=artifacts,
        lineage=tuple(lineage),
        findings=tuple(all_findings),
        waivers=tuple(waiver_results),
    )


def verification_report_json(report: VerificationReport, *, pretty: bool = False) -> str:
    """Serialize a verification report with stable key and collection ordering."""

    return (
        json.dumps(
            report.as_dict(),
            sort_keys=True,
            indent=2 if pretty else None,
            separators=None if pretty else (",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    )


def verification_report_text(report: VerificationReport) -> str:
    """Render a compact verification-lineage report for CI logs."""

    active = [finding for finding in report.findings if finding.waived_by is None]
    lines = [
        f"SchematicAirlock verification: {report.decision.value.upper()}",
        f"manifest: sha256:{report.manifest_sha256}",
        f"evidence assessment date: {report.assessment_date}",
        f"evaluated as of (UTC): {report.evaluated_as_of}",
        (
            f"lineage: {len(report.artifacts)} artifacts, {len(report.lineage)} reports, "
            f"{len(report.waivers)} waivers"
        ),
        f"findings: {len(active)} active, {len(report.findings) - len(active)} waived",
    ]
    for finding in report.findings:
        disposition = (
            f"WAIVED:{finding.waived_by}" if finding.waived_by else finding.severity.value.upper()
        )
        location = finding.source
        if finding.location is not None:
            location += f":{finding.location.line}"
        lines.append(f"- [{disposition}] {finding.rule} {location}: {finding.message}")
    return "\n".join(lines) + "\n"
