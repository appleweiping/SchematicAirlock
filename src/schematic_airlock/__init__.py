"""Public API for SchematicAirlock."""

from schematic_airlock._version import __version__
from schematic_airlock.domain import AuditReport, Decision, Finding, Severity
from schematic_airlock.engine import audit_path, audit_text
from schematic_airlock.fuzzing import FuzzStats, fuzz_smoke
from schematic_airlock.interop import (
    StructuralSummary,
    compare_structural_summary,
    load_structural_summary,
)
from schematic_airlock.policy import AuditPolicy

__all__ = [
    "AuditPolicy",
    "AuditReport",
    "Decision",
    "Finding",
    "FuzzStats",
    "Severity",
    "StructuralSummary",
    "__version__",
    "audit_path",
    "audit_text",
    "compare_structural_summary",
    "fuzz_smoke",
    "load_structural_summary",
]
