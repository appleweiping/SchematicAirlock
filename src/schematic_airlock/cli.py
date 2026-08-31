"""Command-line interface with CI-friendly exit codes."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Never, TextIO

from schematic_airlock._version import __version__
from schematic_airlock.domain import AirlockError, Decision
from schematic_airlock.engine import audit_path
from schematic_airlock.fuzzing import fuzz_smoke
from schematic_airlock.interop import compare_structural_summary, load_structural_summary_path
from schematic_airlock.policy import AuditPolicy
from schematic_airlock.report import explain_finding, load_report_path, report_json, report_text

EXIT_OK = 0
EXIT_GATE = 2
EXIT_INPUT = 3


class _ReturningParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise ValueError(message)


def _parser() -> argparse.ArgumentParser:
    parser = _ReturningParser(
        prog="schematic-airlock",
        description="Deterministically audit a local SPICE artifact without executing it.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)

    audit = subcommands.add_parser("audit", help="audit a file or directory bundle")
    audit.add_argument("path", help="netlist file or bundle directory")
    audit.add_argument("--entry", help="bundle-relative entry netlist")
    audit.add_argument("--policy", help="TOML policy file")
    audit.add_argument("--format", choices=("text", "json"), default="text")
    audit.add_argument("--pretty", action="store_true", help="indent JSON output")
    audit.add_argument("--output", help="write report to this file")
    audit.add_argument(
        "--fail-on",
        choices=("review", "deny"),
        default="review",
        help="minimum decision that produces exit code 2",
    )

    explain = subcommands.add_parser("explain", help="explain one finding in a JSON report")
    explain.add_argument("report", help="JSON report path")
    explain.add_argument("finding_id", help="stable finding ID")

    fingerprint = subcommands.add_parser(
        "fingerprint", help="print the validated policy fingerprint"
    )
    fingerprint.add_argument("--policy", help="TOML policy file")

    policy_check = subcommands.add_parser("policy-check", help="validate a policy file")
    policy_check.add_argument("policy", help="TOML policy file")
    fuzz = subcommands.add_parser("fuzz-smoke", help="run bounded deterministic audit mutations")
    fuzz.add_argument("path", help="single SPICE seed file")
    fuzz.add_argument("--cases", type=int, default=128)
    fuzz.add_argument("--seed", type=int, default=0)
    interop = subcommands.add_parser(
        "interop-check", help="compare an audit with a SpiceTrellis structural summary"
    )
    interop.add_argument("path", help="netlist file or bundle directory")
    interop.add_argument("summary", help="SpiceTrellis --interop JSON path")
    interop.add_argument("--entry", help="bundle-relative entry netlist")
    interop.add_argument("--policy", help="TOML policy file")
    interop.add_argument(
        "--fail-on",
        choices=("review", "deny"),
        default="review",
        help="minimum fresh-audit decision that produces exit code 2",
    )
    return parser


def _write_output(text: str, destination: str | None, stdout: TextIO) -> None:
    if destination is None:
        stdout.write(text)
        return
    path = Path(destination)
    path.write_text(text, encoding="utf-8", newline="\n")


def _audit(args: argparse.Namespace, stdout: TextIO) -> int:
    report = audit_path(args.path, entry=args.entry, policy=args.policy)
    if args.format == "json":
        rendered = report_json(report, pretty=args.pretty)
    else:
        rendered = report_text(report)
    _write_output(rendered, args.output, stdout)
    threshold = Decision.REVIEW if args.fail_on == "review" else Decision.DENY
    return EXIT_GATE if report.decision.rank >= threshold.rank else EXIT_OK


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the CLI and return, rather than raise, the documented exit code."""

    output = stdout or sys.stdout
    errors = stderr or sys.stderr
    try:
        args = _parser().parse_args(argv)
        if args.command == "audit":
            return _audit(args, output)
        if args.command == "explain":
            value = load_report_path(args.report)
            output.write(explain_finding(value, args.finding_id))
            return EXIT_OK
        if args.command == "fingerprint":
            policy = AuditPolicy.from_toml(args.policy) if args.policy else AuditPolicy()
            output.write(policy.fingerprint() + "\n")
            return EXIT_OK
        if args.command == "policy-check":
            policy = AuditPolicy.from_toml(args.policy)
            output.write(f"valid policy: sha256:{policy.fingerprint()}\n")
            return EXIT_OK
        if args.command == "fuzz-smoke":
            stats = fuzz_smoke(
                Path(args.path).read_text(encoding="utf-8-sig"),
                cases=args.cases,
                seed=args.seed,
            )
            output.write(json.dumps(stats.as_dict(), sort_keys=True) + "\n")
            return EXIT_OK
        if args.command == "interop-check":
            report = audit_path(args.path, entry=args.entry, policy=args.policy)
            summary = load_structural_summary_path(args.summary)
            mismatches = compare_structural_summary(report, summary)
            if mismatches:
                output.write("structural summary mismatch: " + "; ".join(mismatches) + "\n")
                return EXIT_GATE
            output.write(f"structural summary verified; audit decision: {report.decision.value}\n")
            threshold = Decision.REVIEW if args.fail_on == "review" else Decision.DENY
            return EXIT_GATE if report.decision.rank >= threshold.rank else EXIT_OK
    except (AirlockError, OSError, UnicodeError, ValueError) as exc:
        errors.write(f"schematic-airlock: {exc}\n")
        return EXIT_INPUT
    return EXIT_INPUT


def entrypoint() -> None:
    """Translate the library-friendly return value into a process exit status."""

    raise SystemExit(main())
