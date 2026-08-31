"""Command-line interface with CI-friendly exit codes."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Never, TextIO

from schematic_airlock.domain import AirlockError, Decision
from schematic_airlock.engine import audit_path
from schematic_airlock.policy import AuditPolicy
from schematic_airlock.report import explain_finding, load_report, report_json, report_text

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
            value = load_report(Path(args.report).read_text(encoding="utf-8"))
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
    except (AirlockError, OSError, UnicodeError, ValueError) as exc:
        errors.write(f"schematic-airlock: {exc}\n")
        return EXIT_INPUT
    return EXIT_INPUT
