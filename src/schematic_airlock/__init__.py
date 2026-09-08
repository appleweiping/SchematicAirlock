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
from schematic_airlock.verification import (
    DigestRecord,
    ToolIdentity,
    VerificationAdapter,
    VerificationArtifact,
    VerificationFinding,
    VerificationLineage,
    VerificationLocation,
    VerificationReport,
    WaiverResult,
    parse_klayout_drc,
    parse_magic_drc,
    parse_magic_pex,
    parse_netgen_lvs,
    verification_report_json,
    verification_report_text,
    verify_path,
)

__all__ = [
    "AuditPolicy",
    "AuditReport",
    "Decision",
    "DigestRecord",
    "Finding",
    "FuzzStats",
    "Severity",
    "StructuralSummary",
    "ToolIdentity",
    "VerificationAdapter",
    "VerificationArtifact",
    "VerificationFinding",
    "VerificationLineage",
    "VerificationLocation",
    "VerificationReport",
    "WaiverResult",
    "__version__",
    "audit_path",
    "audit_text",
    "compare_structural_summary",
    "fuzz_smoke",
    "load_structural_summary",
    "parse_klayout_drc",
    "parse_magic_drc",
    "parse_magic_pex",
    "parse_netgen_lvs",
    "verification_report_json",
    "verification_report_text",
    "verify_path",
]
