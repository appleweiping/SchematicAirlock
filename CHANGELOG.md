# Changelog

All notable changes are recorded here. Versions follow semantic versioning.

## 0.7.0 - 2026-09-09

### Added

- Composite declared DC rail-short paths with bounded shortest-path witnesses,
  exact zero-value intent, and conservative exclusions for opaque/dynamic devices.
- Original strict electrical-rule corpus covering every current electrical rule
  family, primitive inventory, and voltage-envelope outcome with explicit oracles.
- Guarded end-to-end hierarchy scaling with observed materialization counts and
  OS peak-memory measurements; reproducible real ngspice rail/parameter probes.

### Fixed

- Isolate numeric parsing, evaluation and display from the caller's Decimal
  context; reject underflow, out-of-range values, malformed numeric delimiters
  and inexact arithmetic in the electrical-proof profile.
- Resolve final top-level and per-instance parameter declarations, preserving
  instance/body/header/global precedence and reevaluating derived values.
  Cycles, invalid overrides and exhausted work budgets cannot reuse stale values.
- Reject malformed explicit parameter tails and preserve earlier malformed
  declaration findings even if a later override supplies a valid value.
- Check parameter-dependent voltage and passive values from reached final
  bindings; preserve literal artifact diagnostics for dormant definitions.
- Prevent opaque R/L/V modifiers and reconfigured SPICE ground from supporting
  false short-intent proofs. R=0 is not claimed to be exact simulator resistance.

## 0.6.0 - 2026-09-09

### Added

- Exact bounded sparse modified nodal analysis for nonnegative resistors and
  independent DC sources, with independent current/voltage/power residual
  verification and explicit singular, inconsistent and budget failures.
- Closed literal R/V/I hierarchical netlist adapter, source-bound reports and
  `linear-dc` CLI. Unsupported semantics never produce partial electrical values.
- Independent dense Gauss-Jordan differential oracle (10,000 random networks)
  and four real ngspice operating-point integration cases with ten voltage probes.

### Fixed

- Stop repeated include expansion after recording its existing unsupported
  diagnostic, preventing exponentially repeated visits through a small DAG.
- Enforce the reached-instance allocation cap within every hierarchy scope,
  including flat primitive lists and sibling instances.
- Reject malformed nameless subcircuit headers with typed syntax diagnostics.
- Reject Unicode-confusable literal scales and quoted electrical expressions
  in the closed linear DC profile while retaining quoted include paths/titles.

## 0.5.0 - 2026-09-09

### Added

- Exact rational DC voltage-difference solver with weighted equality elimination,
  negative-cycle detection, sparse pairwise bounds and cumulative work budgets.
- Explicit net/source envelopes, expected-power ranges, six signed MOS terminal
  ratings and diode forward/reverse voltage checks; unknown and partial results
  never become passes. Versioned rules/report schemas, public API and CLI.
- Independent all-pairs oracle tests, original illustrative model-rating example,
  hierarchical/source-location evidence and Unicode display-control protection.
- Trusted-base DCO verification binding PR base/head/count, rerunning on retarget
  edits and resetting pending status before verification.

### Fixed

- Preserve parent-internal net identity when binding nested subcircuit ports.
- Release evidence now checks the required SPDX 2.3 document-header profile
  before binding or accepting installed-package files. This is a release-profile
  check, not a general SPDX conformance validator.

## 0.4.1 - 2026-09-08

### Fixed

- Release SBOMs now scan the isolated environment containing the installed wheel with a pinned
  Syft version, and offline validation requires the exact package version plus document-to-package
  and package-to-file SPDX relationships.
- Release handoffs now admit exactly the wheel, source distribution, SPDX SBOM, and checksum
  manifest, and re-verify the asset allowlist and every checksum after each download.
- Bind every installed RECORD entry (including the console launcher) to checked wheel content
  and SPDX checksums. Reject noncanonical package locators and unsafe distribution members.
- Manual release rehearsals require a signed version tag and successful main-push CI;
  distribution auditing runs in the frozen package environment.

## 0.4.0 - 2026-09-07

### Added

- Offline Magic DRC, KLayout DRC, Netgen LVS, and Magic PEX report adapters with bounded,
  fail-closed parsing profiles and a common versioned finding shape.
- Content-bound schematic, layout, PEX, report, input, and output lineage with a cross-view
  completeness gate and deterministic SHA-256 records.
- Exact, expiring, one-to-one waivers with visible applied, expired, and unused dispositions.
- `verification-check` CLI, stable Python API, Draft 2020-12 manifest/report schemas, original
  synthetic fixtures, threat-model documentation, and verification workload counters.
- Checkout-independent report identity (`root` is the logical `.`), so identical bundles in
  different workspaces serialize identically.

### Security

- Verification manifests reject duplicate or aliased paths, traversal and symlink escapes,
  duplicate identifiers, non-finite/out-of-range coordinates, contradictory tool results,
  ambiguous waiver matches, and fixed resource-limit overruns without running external tools.
- Portable paths require NFC Unicode; hidden XML mixed/nested content and total finding counts
  beyond the report schema ceiling are rejected instead of being silently ignored.
- Public report-adapter inputs enforce the same two-MiB byte ceiling as bundle reports and reject
  non-scalar Unicode before XML parsing, hashing, or serialization.
- Public report adapters reject non-text values and Unicode controls or directional separators,
  and enforce the character lower bound before allocating an encoded copy.
- Waivers are bound to the exact finding fingerprint, including tool version, message, location,
  bounding box, and objects; a changed diagnostic cannot silently inherit an older waiver.
- Audit and verification reports use atomic no-clobber file output; replacement requires explicit
  `--force`, while an output that aliases any audited input remains forbidden even when forced.
- Release assets include a pinned-tool SPDX 2.3 SBOM and verified SHA-256 checksums alongside
  GitHub build provenance attestations.
- Pull requests enforce author-matching DCO trailers, and release workflows cryptographically
  verify signed tags against the repository's auditable allowed-signers policy.
- Verification waivers bind the full 256-bit finding fingerprint rather than a truncated display
  hash, so adversarial collisions cannot transfer a reviewed waiver to a different finding.

## 0.3.0 - 2026-09-07

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
