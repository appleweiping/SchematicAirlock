"""Deterministic adversarial probes for the Airlock audit boundary."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import blake2s

from schematic_airlock.domain import AirlockError
from schematic_airlock.engine import audit_text

_INSERTIONS = (
    "\n.include ../outside.lib\n",
    "\n.control\nshell echo blocked\n.endc\n",
    "\n* airlock probe\n",
    "\x00",
)


@dataclass(frozen=True, slots=True)
class FuzzStats:
    """Reproducible counters from an audit mutation run."""

    cases: int
    bytes_examined: int
    findings: int
    rejected: int

    def as_dict(self) -> dict[str, int]:
        return {
            "bytes_examined": self.bytes_examined,
            "cases": self.cases,
            "findings": self.findings,
            "rejected": self.rejected,
        }


def _probe(source: str, ordinal: int, campaign: int) -> str:
    """Build one size-bounded mutation plan from stable campaign coordinates."""

    token = blake2s(f"airlock/{campaign}/{ordinal}".encode(), digest_size=16).digest()
    if source == "":
        return ".control\n.endc\n"
    pivot = int.from_bytes(token[:4], "little") % (len(source) + 1)
    operation = token[4] % 4
    if operation == 0:
        return source[:pivot]
    if operation == 1:
        end = min(len(source), pivot + 1 + token[5] % 8)
        return source[:pivot] + source[pivot:end] * 2 + source[end:]
    if operation == 2 and pivot < len(source):
        replacement = chr(1 + token[5] % 31)
        return source[:pivot] + replacement + source[pivot + 1 :]
    insertion = _INSERTIONS[token[5] % len(_INSERTIONS)]
    return source[:pivot] + insertion + source[pivot:]


def fuzz_smoke(text: str, *, cases: int = 128, seed: int = 0) -> FuzzStats:
    """Run bounded audit-specific probes without executing any deck content."""

    if type(cases) is not int or cases < 1 or cases > 10_000:
        raise ValueError("cases must be an integer from 1 through 10000")

    total_bytes = 0
    finding_count = 0
    rejection_count = 0
    for ordinal in range(cases):
        candidate = _probe(text, ordinal, seed)
        total_bytes += len(candidate.encode("utf-8"))
        try:
            finding_count += len(audit_text(candidate).findings)
        except AirlockError:
            rejection_count += 1
    return FuzzStats(cases, total_bytes, finding_count, rejection_count)
