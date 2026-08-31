"""Strict consumer for the portable structural-summary interchange contract."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from schematic_airlock._strict_json import load_strict_json, load_strict_json_path
from schematic_airlock.domain import AuditReport, InputError

SCHEMA = "org.spice-tools.structural-summary"


def _exact(value: Mapping[str, object], keys: set[str], context: str) -> None:
    if set(value) != keys:
        raise InputError(f"{context} fields are invalid")


def _portable_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


@dataclass(frozen=True, slots=True)
class StructuralSummary:
    files: tuple[tuple[str, int, str], ...]
    file_count: int
    includes: int
    subcircuits: int
    element_families: tuple[tuple[str, int], ...]
    parameters: tuple[str, ...]
    models: tuple[str, ...]


def load_structural_summary(text: str) -> StructuralSummary:
    """Decode the untrusted, observation-only SpiceTrellis summary."""

    value = load_strict_json(text, context="interop JSON")
    return _load_structural_summary_value(value)


def _load_structural_summary_value(value: object) -> StructuralSummary:
    """Validate an already strictly decoded structural-summary value."""

    if not isinstance(value, Mapping):
        raise InputError("interop root must be an object")
    _exact(value, {"schema", "schema_version", "producer", "files", "structure"}, "interop")
    if (
        value["schema"] != SCHEMA
        or isinstance(value["schema_version"], bool)
        or not isinstance(value["schema_version"], int)
        or value["schema_version"] != 1
    ):
        raise InputError("unsupported structural-summary schema")
    producer = value["producer"]
    if not isinstance(producer, Mapping):
        raise InputError("interop producer must be an object")
    _exact(producer, {"name", "version"}, "interop producer")
    if (
        producer["name"] != "SpiceTrellis"
        or not isinstance(producer["version"], str)
        or not producer["version"]
    ):
        raise InputError("interop producer is invalid")
    raw_files = value["files"]
    if not isinstance(raw_files, list) or not raw_files:
        raise InputError("interop files must be a non-empty array")
    files: list[tuple[str, int, str]] = []
    names: set[str] = set()
    for item in raw_files:
        if not isinstance(item, Mapping):
            raise InputError("interop file entry must be an object")
        _exact(item, {"path", "bytes", "sha256"}, "interop file")
        path, size, digest = item["path"], item["bytes"], item["sha256"]
        if (
            not _portable_path(path)
            or path.casefold() in names
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise InputError("interop file entry is invalid")
        names.add(path.casefold())
        files.append((path, size, digest))
    structure = value["structure"]
    if not isinstance(structure, Mapping):
        raise InputError("interop structure must be an object")
    _exact(
        structure,
        {"files", "includes", "subcircuits", "element_families", "parameters", "models"},
        "interop structure",
    )
    counts: list[int] = []
    for key in ("files", "includes", "subcircuits"):
        count = structure[key]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise InputError(f"interop structure {key} must be a non-negative integer")
        counts.append(count)
    families = structure["element_families"]
    if not isinstance(families, Mapping):
        raise InputError("interop element_families must be an object")
    family_items: list[tuple[str, int]] = []
    family_names: set[str] = set()
    for name, count in families.items():
        if (
            not isinstance(name, str)
            or not name
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
            or name.casefold() in family_names
        ):
            raise InputError("interop element family entry is invalid")
        family_names.add(name.casefold())
        family_items.append((name, count))
    structural_names: dict[str, tuple[str, ...]] = {}
    for key in ("parameters", "models"):
        items = structure[key]
        if (
            not isinstance(items, list)
            or not all(isinstance(item, str) and item for item in items)
            or len({item.casefold() for item in items}) != len(items)
        ):
            raise InputError(f"interop structure {key} must be an array of strings")
        structural_names[key] = tuple(sorted(item.casefold() for item in items))
    if counts[0] != len(files):
        raise InputError("interop file count does not match file records")
    return StructuralSummary(
        tuple(files),
        counts[0],
        counts[1],
        counts[2],
        tuple(sorted((name.upper(), count) for name, count in family_items)),
        structural_names["parameters"],
        structural_names["models"],
    )


def load_structural_summary_path(path: str | Path) -> StructuralSummary:
    """Read a summary through the same bounded, strict trust boundary."""

    value = load_strict_json_path(path, context="interop JSON")
    # Re-encode through the public text loader to retain one contract validator.
    # The document is already bounded and strict, so this is only structural dispatch.
    return _load_structural_summary_value(value)


def compare_structural_summary(report: AuditReport, summary: StructuralSummary) -> tuple[str, ...]:
    """Compare shared structural facts without changing the airlock decision."""

    mismatches: list[str] = []
    report_files = {(item.path, item.size, item.sha256) for item in report.files}
    if report_files != set(summary.files):
        mismatches.append("file records differ")
    if report.stats.files != summary.file_count:
        mismatches.append("file counts differ")
    if report.stats.subcircuits != summary.subcircuits:
        mismatches.append("subcircuit counts differ")
    if report.structure.includes != summary.includes:
        mismatches.append("include counts differ")
    if report.structure.element_families != summary.element_families:
        mismatches.append("element families differ")
    if report.structure.parameters != summary.parameters:
        mismatches.append("parameter names differ")
    if report.structure.models != summary.models:
        mismatches.append("model names differ")
    return tuple(mismatches)
