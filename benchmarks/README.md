# Benchmarks

Run `python benchmarks/benchmark.py --iterations 25` from an installed development environment.
The JSON records a content-derived workload hash and deterministic work counts. Timing is diagnostic:
compare it only on the same machine, interpreter, power mode, and checkout. It is not a CI threshold.

The [end-to-end hierarchy scaling benchmark](../docs/hierarchy-scaling.md)
generates a compact fan-out deck and runs the complete `audit_path` pipeline in
an OS-monitored child. Its closed-form 10k, 100k, and one-million-resistor
profiles are distinct from kernel-only measurements and have fail-closed 3 GiB
and 180-second ceilings.

The [ngspice 42 rail-intent oracle](../docs/ngspice-rail-oracle.md) replays nine
immutable R/L/V boundary decks plus nine parameter-scope and dependency decks
with a caller-supplied, exact-hash executable. It does not download or search
for ngspice, and its subprocess time and output are bounded. The checked-in JSON
is a real official-binary observation, not a controlled-fixture substitute.

Each iteration also verifies the original synthetic DRC/LVS/PEX bundle under
`tests/fixtures/verification_bundle`. Its deterministic counters cover four content-bound lineage
records and the waiver path; no external EDA process runs. The corpus and its license/provenance
are recorded in `manifest.json`.

The [v0.7 source-bound regression run](results/erc-v070-regression-20260909.json)
used Windows and CPython 3.11.2 for 25 iterations: median 98.2403 ms, minimum
83.9236 ms. These are host-specific diagnostics, not speedup claims. The two
original decks still contain 23 devices. Correct final parameter binding removes
the earlier nine spurious unresolved-passive findings, yielding zero audit
findings; the separate verification fixture still produces its one expected
finding and four lineage records. Workload hashes are unchanged.
