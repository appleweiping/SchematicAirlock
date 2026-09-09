"""Compare exact linear DC results with an actual ngspice operating-point run.

The fixed original experiments are generated here; no user netlist is executed.
This harness is opt-in integration evidence, not part of the offline audit API.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import subprocess
import tempfile
from fractions import Fraction
from pathlib import Path

from schematic_airlock import dc_netlist, linear_dc, solve_dc_text

CASES = (
    ("divider", "V1 rail 0 5\nR1 rail out 2k\nR2 out 0 3k\n", ("rail", "out")),
    ("floating_source", "V1 a b 4\nR1 b 0 3k\nI1 0 a 1m\n", ("a", "b")),
    (
        "bridge",
        "V1 rail 0 6\nR1 rail a 2k\nR2 a 0 3k\nR3 rail b 4k\nR4 b 0 5k\nR5 a b 7k\n",
        ("rail", "a", "b"),
    ),
    ("two_supplies", "V1 a 0 5\nV2 b a 2\nR1 b c 3k\nR2 c 0 4k\nI1 c 0 100u\n", ("a", "b", "c")),
)


def check_table(text: str, names: tuple[str, ...], expected: dict[str, Fraction]) -> float:
    rows = [line.split() for line in text.splitlines() if line.strip()]
    if len(rows) != 2 or len(rows[0]) != len(names) + 1 or len(rows[1]) != len(names) + 1:
        raise AssertionError("ngspice output is not exactly one complete requested OP row")
    if rows[0][1:] != [f"v({name})" for name in names]:
        raise AssertionError("ngspice output probes differ from the fixed experiment")
    values = [float(token) for token in rows[1]]
    if not all(math.isfinite(value) for value in values):
        raise AssertionError("ngspice OP output contains a non-finite value")
    maximum = 0.0
    for name, actual in zip(names, values[1:], strict=True):
        reference = float(expected[name])
        error = abs(actual - reference)
        if error > 1e-11 + 1e-11 * abs(reference):
            raise AssertionError(f"ngspice V({name}) differs from the exact linear solution")
        maximum = max(maximum, error)
    return maximum


def run(executable: str) -> dict[str, object]:
    resolved = shutil.which(executable)
    if resolved is None:
        raise RuntimeError("a real ngspice executable is required")
    command = str(Path(resolved).resolve())
    version = subprocess.run(
        [command, "--version"], check=True, capture_output=True, text=True, timeout=20
    ).stdout
    records = []
    with tempfile.TemporaryDirectory(prefix="airlock-linear-dc-oracle-") as directory:
        root = Path(directory)
        for label, circuit, names in CASES:
            oracle = solve_dc_text("* Original linear DC comparison\n" + circuit + ".end\n")
            if oracle.status != "solved" or oracle.solution is None:
                raise AssertionError("fixed exact oracle must solve")
            deck = (
                "* Original linear DC comparison\n"
                + circuit
                + ".control\nset wr_vecnames\nset wr_singlescale\nset numdgt=17\nop\n"
                + "wrdata result.txt "
                + " ".join(f"v({name})" for name in names)
                + "\nquit\n.endc\n.end\n"
            )
            case = root / label
            case.mkdir()
            (case / "circuit.sp").write_text(deck, encoding="ascii", newline="\n")
            subprocess.run(
                [command, "-n", "-b", "-o", "ngspice.log", "circuit.sp"],
                cwd=case,
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            artifact = case / "result.txt"
            with artifact.open("rb") as stream:
                raw = stream.read(64 * 1024 + 1)
            if len(raw) > 64 * 1024:
                raise AssertionError("fixed operating-point output exceeds its byte budget")
            maximum = check_table(raw.decode("ascii"), names, dict(oracle.solution.voltages))
            records.append(
                {
                    "case": label,
                    "deck_sha256": hashlib.sha256(deck.encode("ascii")).hexdigest(),
                    "artifact_sha256": hashlib.sha256(raw).hexdigest(),
                    "probes": len(names),
                    "max_absolute_error_volts": maximum,
                    "network_id": oracle.solution.network_id,
                }
            )
    return {
        "schema": "org.schematic-airlock.linear-dc-ngspice-evidence",
        "version": 1,
        "evidence_class": "real-executable",
        "simulator_version": version.strip(),
        "executable_sha256": hashlib.sha256(Path(command).read_bytes()).hexdigest(),
        "kernel_sha256": hashlib.sha256(Path(linear_dc.__file__).read_bytes()).hexdigest(),
        "adapter_sha256": hashlib.sha256(Path(dc_netlist.__file__).read_bytes()).hexdigest(),
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "absolute_tolerance_volts": 1e-11,
        "relative_tolerance": 1e-11,
        "cases": records,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ngspice", default="ngspice")
    args = parser.parse_args()
    print(json.dumps(run(args.ngspice), sort_keys=True, indent=2, allow_nan=False))
