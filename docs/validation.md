# Validation assets

The `corpus/portable_analog` decks are clean-room, MIT-licensed fixtures. They model common
hierarchical and passive front-end shapes without simulation-accurate device models or PDK data.
Their exact hashes and provenance are recorded in `benchmarks/manifest.json`.

`schematic-airlock fuzz-smoke FILE --cases 128 --seed 0` performs bounded deterministic byte-level
mutations. Rejected malformed cases are counted and expected; unexpected exceptions fail the run.
It is a robustness smoke test, not exhaustive fuzzing.

`schematic-airlock interop-check ARTIFACT SUMMARY.json` consumes version 1 of
`org.spice-tools.structural-summary`. JSON is parsed strictly, paths are confined, file bytes are
verified, and shared structural counts are compared against a fresh audit. A match never changes
the policy decision and cannot bypass the normal audit. The default
`--fail-on review` returns exit code 2 for either `review` or `deny`, while
`--fail-on deny` permits review findings but still blocks deny findings.

The files in `docs/schemas` publish Draft 2020-12 contracts for bundle manifests, audit reports,
and structural summaries. Runtime loading is deliberately stricter than schema-only validation:
all three JSON trust boundaries reject duplicate keys, non-finite or oversized numbers, excessive
nesting/value counts, and documents over 1 MiB. Contract-specific validation also rejects unknown
fields, ambiguous schema-version types, case-folded name collisions, inconsistent counts, and
non-portable paths. Parser recursion and numeric failures are reported as normal input errors.

Filesystem inputs are read with `BundleLimits`: each read stops at the smaller of the remaining
total budget and the per-file budget plus one detection byte. Oversized bundles and interchange
files are therefore rejected without first loading the complete file into memory.

Run `python benchmarks/benchmark.py --iterations 25` for the reproducible workload. The content
hash binds every audited deck and followed local library; device count and finding count are also
regression contracts. The output also records installed distribution version, an unambiguous hash
of the imported package's Python tree, and the executing benchmark harness hash. Elapsed time is
comparable only in a controlled environment.
