# Benchmarks

Run `python benchmarks/benchmark.py --iterations 25` from an installed development environment.
The JSON records a content-derived workload hash and deterministic work counts. Timing is diagnostic:
compare it only on the same machine, interpreter, power mode, and checkout. It is not a CI threshold.

Each iteration also verifies the original synthetic DRC/LVS/PEX bundle under
`tests/fixtures/verification_bundle`. Its deterministic counters cover four content-bound lineage
records and the waiver path; no external EDA process runs. The corpus and its license/provenance
are recorded in `manifest.json`.
