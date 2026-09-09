"""Original exact-source-chain kernel benchmark; not a netlist-scale claim."""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import statistics
import time
import tracemalloc
from fractions import Fraction
from pathlib import Path

import schematic_airlock.voltage_constraints as implementation
from schematic_airlock import __version__
from schematic_airlock.voltage_constraints import (
    VoltageConstraint,
    VoltageInterval,
    VoltageLimits,
    VoltageSystem,
)


def run(count: int, repetitions: int = 3) -> dict[str, object]:
    if type(count) is not int or not 1 <= count <= 1_000_000:
        raise ValueError("source count must be an integer in 1..1000000")
    if type(repetitions) is not int or not 1 <= repetitions <= 10:
        raise ValueError("repetitions must be an integer in 1..10")
    if tracemalloc.is_tracing():
        raise ValueError("benchmark requires its own tracemalloc session")
    limits = VoltageLimits(max_nodes=count + 1, max_constraints=count, max_edge_visits=1)
    step = VoltageInterval(Fraction(1, 1000), Fraction(1, 1000))
    elapsed: list[float] = []
    peaks: list[int] = []
    expected = VoltageInterval(Fraction(count, 1000), Fraction(count, 1000))
    for _ in range(repetitions):
        gc.collect()
        tracemalloc.start()
        try:
            started = time.perf_counter_ns()
            system = VoltageSystem(
                (f"n{index}" for index in range(count + 1)),
                (
                    VoltageConstraint(f"n{index}", f"n{index - 1}", step, f"v{index}")
                    for index in range(1, count + 1)
                ),
                limits=limits,
            )
            observed = system.difference(f"n{count}", "n0")
            elapsed.append((time.perf_counter_ns() - started) / 1_000_000)
            peaks.append(tracemalloc.get_traced_memory()[1])
            if observed != expected or system.component_count != 1 or system.edge_visits != 0:
                raise AssertionError("source-chain closed-form oracle failed")
        finally:
            tracemalloc.stop()
        del system
    descriptor = {
        "name": "original-exact-series-source-chain",
        "sources": count,
        "step_volts": "1/1000",
    }
    return {
        "schema": "org.schematic-airlock.voltage-kernel-benchmark",
        "version": 1,
        "tool_version": __version__,
        "workload": descriptor,
        "repetitions": repetitions,
        "workload_sha256": hashlib.sha256(
            json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "implementation_sha256": hashlib.sha256(
            Path(implementation.__file__).read_bytes()
        ).hexdigest(),
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "median_ms": statistics.median(elapsed),
        "maximum_ms": max(elapsed),
        "peak_python_traced_bytes": max(peaks),
        "edge_visits": 0,
        "components": 1,
        "observed": observed.as_dict(),
        "closed_form_oracle_passed": True,
        "scope": "constraint kernel; excludes netlist parsing and nonlinear/ERC coverage",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=int, default=100_000)
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()
    print(json.dumps(run(args.sources, args.repetitions), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
