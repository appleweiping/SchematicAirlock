"""Public orchestration API for offline artifact audits."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from schematic_airlock.bundle import ArtifactBundle, BundleLimits, BundleSource, MemoryBundle
from schematic_airlock.checks import CheckContext, run_checks
from schematic_airlock.circuit_graph import build_circuit_graph
from schematic_airlock.domain import (
    AuditReport,
    AuditStats,
    AuditStructure,
    Decision,
    Finding,
    Severity,
)
from schematic_airlock.include_graph import load_include_graph
from schematic_airlock.policy import AuditPolicy, load_policy


def _decision(findings: tuple[Finding, ...]) -> Decision:
    if any(finding.severity is Severity.DENY for finding in findings):
        return Decision.DENY
    if any(finding.severity is Severity.REVIEW for finding in findings):
        return Decision.REVIEW
    return Decision.ALLOW


def _risk_score(findings: tuple[Finding, ...]) -> int:
    """Calculate a bounded score that is stable but not a probability."""

    weights = {Severity.INFO: 1, Severity.REVIEW: 9, Severity.DENY: 32}
    per_code: dict[str, int] = {}
    for finding in findings:
        per_code[finding.code] = min(45, per_code.get(finding.code, 0) + weights[finding.severity])
    return min(100, sum(per_code.values()))


def _structure(includes: object, graph: object) -> AuditStructure:
    """Collect the contract subset without trusting a producer summary."""

    from schematic_airlock.circuit_graph import CircuitGraph
    from schematic_airlock.include_graph import IncludeGraph

    if not isinstance(includes, IncludeGraph) or not isinstance(graph, CircuitGraph):
        raise TypeError("structural facts require parsed include and circuit graphs")
    parameters: set[str] = set()
    models: set[str] = set()
    include_count = 0
    for deck in includes.decks:
        include_count += len(deck.includes)
        for directive in deck.directives:
            if directive.name == "param":
                parameters.update(
                    item.split("=", 1)[0].casefold()
                    for item in directive.arguments
                    if "=" in item and item.split("=", 1)[0]
                )
            elif directive.name == "model" and directive.arguments:
                models.add(directive.arguments[0].casefold())
        for subcircuit in deck.subcircuits:
            parameters.update(name.casefold() for name, _value in subcircuit.parameters)
            for directive in subcircuit.directives:
                if directive.name == "param":
                    parameters.update(
                        item.split("=", 1)[0].casefold()
                        for item in directive.arguments
                        if "=" in item and item.split("=", 1)[0]
                    )
                elif directive.name == "model" and directive.arguments:
                    models.add(directive.arguments[0].casefold())
    families = Counter(device.element.kind.upper() for device in graph.devices)
    return AuditStructure(
        include_count,
        tuple(sorted(families.items())),
        tuple(sorted(parameters)),
        tuple(sorted(models)),
    )


def _audit_bundle(bundle: BundleSource, policy: AuditPolicy) -> AuditReport:
    includes = load_include_graph(bundle, max_depth=policy.limits.max_include_depth)
    graph = build_circuit_graph(
        includes, max_expanded_instances=policy.limits.max_expanded_instances
    )
    findings = run_checks(CheckContext(bundle, includes, graph, policy))
    digests = bundle.digests()
    stats = AuditStats(
        files=len(digests),
        bytes=sum(item.size for item in digests),
        logical_lines=graph.logical_lines,
        devices=len(graph.devices),
        nets=len(graph.nets),
        subcircuits=len(graph.subcircuits),
        expanded_instances=graph.expanded_instances,
    )
    return AuditReport(
        decision=_decision(findings),
        risk_score=_risk_score(findings),
        root=bundle.root_display,
        entry=bundle.entry,
        bundle_sha256=bundle.bundle_hash(),
        policy_sha256=policy.fingerprint(),
        files=digests,
        findings=findings,
        stats=stats,
        structure=_structure(includes, graph),
    )


def audit_path(
    path: str | Path,
    *,
    entry: str | None = None,
    policy: AuditPolicy | str | Path | None = None,
) -> AuditReport:
    """Audit one local file or a confined directory bundle."""

    selected_policy = load_policy(policy)
    limits = BundleLimits(
        max_files=selected_policy.limits.max_files,
        max_total_bytes=selected_policy.limits.max_total_bytes,
        max_file_bytes=selected_policy.limits.max_file_bytes,
    )
    bundle = ArtifactBundle.open(path, entry=entry, limits=limits)
    return _audit_bundle(bundle, selected_policy)


def audit_text(
    text: str,
    *,
    virtual_name: str = "input.sp",
    policy: AuditPolicy | str | Path | None = None,
) -> AuditReport:
    """Audit an in-memory single-file deck.

    Includes are reported as denied because no ambient filesystem lookup is
    performed for in-memory audits.
    """

    selected_policy = load_policy(policy)
    return _audit_bundle(MemoryBundle(text, virtual_name), selected_policy)
