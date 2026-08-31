"""Public API for SchematicAirlock."""

from schematic_airlock.domain import AuditReport, Decision, Finding, Severity
from schematic_airlock.engine import audit_path, audit_text
from schematic_airlock.policy import AuditPolicy

__all__ = [
    "AuditPolicy",
    "AuditReport",
    "Decision",
    "Finding",
    "Severity",
    "audit_path",
    "audit_text",
]

__version__ = "0.1.0"
