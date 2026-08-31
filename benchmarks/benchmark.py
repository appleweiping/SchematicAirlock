"""Reproducible corpus benchmark with deterministic work counters."""

from __future__ import annotations

import argparse
import json
import statistics
from hashlib import sha256
from importlib.metadata import version
from pathlib import Path
from time import perf_counter

import schematic_airlock
from schematic_airlock import audit_path

ROOT = Path(__file__).parents[1]
CORPUS = ROOT / "corpus" / "portable_analog"
DECKS = tuple(sorted(CORPUS.glob("*.sp")))
WORKLOAD_FILES = tuple(sorted((*CORPUS.glob("*.sp"), *CORPUS.glob("*.lib"))))


def _package_tree_sha256() -> str:
    if schematic_airlock.__file__ is None:
        raise RuntimeError("cannot locate imported schematic_airlock package")
    root = Path(schematic_airlock.__file__).resolve().parent
    digest = sha256()
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root).as_posix().encode()
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def run(iterations: int) -> dict[str, object]:
    if (
        isinstance(iterations, bool)
        or not isinstance(iterations, int)
        or not 1 <= iterations <= 10_000
    ):
        raise ValueError("iterations must be an integer between 1 and 10000")
    samples: list[float] = []
    devices = findings = 0
    digest = sha256()
    for path in WORKLOAD_FILES:
        relative = path.relative_to(CORPUS).as_posix().encode()
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    for _ in range(iterations):
        started = perf_counter()
        current_devices = current_findings = 0
        for path in DECKS:
            report = audit_path(path)
            current_devices += report.stats.devices
            current_findings += len(report.findings)
        samples.append((perf_counter() - started) * 1000)
        devices, findings = current_devices, current_findings
    return {
        "schema_version": 1,
        "tool": "SchematicAirlock",
        "distribution_version": version("schematic-airlock"),
        "package_tree_sha256": _package_tree_sha256(),
        "harness_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "workload_sha256": digest.hexdigest(),
        "iterations": iterations,
        "decks_per_iteration": len(DECKS),
        "devices_per_iteration": devices,
        "findings_per_iteration": findings,
        "median_ms": round(statistics.median(samples), 6),
        "minimum_ms": round(min(samples), 6),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=25)
    args = parser.parse_args()
    print(json.dumps(run(args.iterations), indent=2, sort_keys=True))
