# Changelog

All notable changes are recorded here. Versions follow semantic versioning.

## Unreleased

### Added

- `SOLVE002`: nodes with no conducting path to ground, the condition behind the most common
  first-run simulator failure. Reported per stranded island rather than per node, since one
  missing connection strands a whole island and a finding per node would report one defect many
  times. The finding names the island and the devices touching it.
- `SOLVE003`: a loop made only of ideal voltage sources. This generalizes the parallel case
  `SRC001` already covered -- two sources across one node pair is the same defect as three
  around a triangle -- and names every source in the loop rather than the one that closed it,
  because the closing edge alone is not something an engineer can act on. One finding per
  independent cycle, so a mesh of sources does not report every path around it.
- `SOLVE001`: a deck that references no configured ground net. Raised once for the whole deck
  rather than once per node, because a naming mismatch or a fragment is one problem however
  many nodes it strands. A subcircuit library that is never called expands to nothing and
  raises none of these.
- `schematic_airlock.solvability` as a Python API: `conducting_pairs`, `floating_islands`,
  `voltage_source_loops`, and `has_ground`.

### Notes

- What conducts at DC is now stated explicitly rather than implied. Capacitors and ideal
  current sources do not tie their nodes together; a MOS gate is insulated while its other
  terminals conduct; a bipolar base conducts because it is a junction.
- A subcircuit call that could not be expanded, and any unrecognized element kind, is treated
  as connecting all of its pins. That assumption can hide a defect and can never refuse an
  artifact because part of it was unreadable, which is the direction a gate must err in.
- Neither check consults a device model, so neither knows whether a transistor is biased on.
  Both describe topology, which is the level at which a simulator refuses the matrix.

## 0.2.0 - 2026-08-31

### Added

- Clean-room portable analog corpus, deterministic fuzz smoke runner, and reproducible benchmark.
- Strict comparison of content-bound SpiceTrellis summaries without weakening audit decisions.
- Bounded strict manifest, report, and interchange JSON with published schemas and explicit
  size, depth, value-count, numeric, and duplicate-key limits.
- Distribution-backed runtime, report, and command-line version metadata.

## 0.1.0 - 2026-08-31

### Added

- Confined file and directory artifact bundles with strict manifests.
- Bounded SPICE lexer, parser, include loader, and hierarchy graph.
- Structural, resource, directive, connectivity, and literal electrical checks.
- Deterministic text and JSON reports with stable finding identifiers.
- Strict TOML policy, Python API, and CI-oriented command-line interface.
