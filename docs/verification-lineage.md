# Physical-verification lineage

`schematic-airlock verification-check` is an offline gate for already-produced DRC, LVS, and
PEX evidence. It does not install or run an EDA tool. The producing workflow writes a small
`verification.json` beside its artifacts and reports; SchematicAirlock confines every path to
that directory, hashes every byte it reads, normalizes supported findings, and evaluates the
cross-view lineage.

An `allow` decision means that the submitted evidence is complete under this contract and has
no active finding at review or deny severity. It does **not** certify a foundry deck, a layout,
a schematic, an extracted model, or the EDA tools that produced them.

## Manifest and lineage contract

The input schema is [verification-manifest-v1.schema.json](schemas/verification-manifest-v1.schema.json).
The output schema is [verification-report-v1.schema.json](schemas/verification-report-v1.schema.json).
Runtime validation is intentionally stricter than portable JSON Schema regexes for NFC normalization
and the complete Unicode `Cc`, `Cf`, `Cs`, `Zl`, and `Zp` category sets.
Both are Draft 2020-12 JSON Schemas; runtime validation is stricter where JSON Schema cannot
express case-insensitive uniqueness, filesystem confinement, or cross-record references.

```json
{
  "schema_version": 1,
  "assessment_date": "2026-09-07",
  "artifacts": [
    {"id": "schematic", "kind": "schematic", "path": "design.sp"},
    {"id": "layout", "kind": "layout", "path": "design.gds"},
    {"id": "pex", "kind": "pex", "path": "design.pex.sp"}
  ],
  "reports": [
    {
      "id": "netgen_lvs",
      "adapter": "netgen-lvs",
      "path": "reports/netgen.lvs",
      "tool": {"name": "Netgen", "version": "1.5.290"},
      "inputs": ["schematic", "layout"],
      "outputs": []
    }
  ],
  "waivers": []
}
```

The complete gate requires exactly one artifact in each `schematic`, `layout`, and `pex` role,
plus these edges:

| Evidence | Required content-bound edge |
| --- | --- |
| Magic or KLayout DRC | `layout` input, no output |
| Netgen LVS | `schematic` and `layout` inputs, no output |
| Magic PEX | `layout` input and `pex` output |

Every artifact, tool report, lineage input, and lineage output carries its observed size and
SHA-256 in the output. A report cannot produce an artifact already produced by another report,
and one path cannot be aliased through two manifest records. Missing views or edges are deny
findings; malformed, ambiguous, or unsafe manifests are input errors. The output `root` is the
portable logical value `.`; host-absolute paths are intentionally excluded, so byte-identical
bundles copied to another checkout produce identical content identities. Reports also record the
gate's UTC evaluation date, so their waiver disposition can intentionally change as time advances.

Manifest `assessment_date` records when the submitted evidence was assessed; it is provenance,
not a clock controlled by the submitter. The gate records its independently derived date as
`evaluated_as_of` and uses only that date for waiver expiration. A future evidence date is rejected.
The Python API permits an explicit `as_of` only for deliberate historical replay; the CLI always
uses the current UTC date and offers no backdating option.

## Adapter profiles

The adapters intentionally accept bounded profiles rather than every human-oriented variation
ever printed by a tool. Unknown records are rejected when accepting them could change the gate.
The fixtures are clean-room examples written for this project; they are not copied tool output,
foundry rules, or sign-off decks.

### Magic DRC

The line-oriented profile accepts a cell, one or more rules, and optional boxes:

```text
Cell: demo_core
Rule: M1.MIN_SPACE | Metal-1 shapes are closer than the project minimum
Box: 1.0 2.0 1.2 2.1 | objects=M1,net_out
```

`No DRC errors found.` or `Total DRC errors: 0` is the clean terminal form. Coordinates are
finite micrometre values in `(left, bottom, right, top)` order. Each box becomes a deny finding.

### KLayout DRC

The adapter reads a bounded UTF-8 native `report-database` XML document. It supports the flat
category/cell subset used by DRC marker databases: a category name is the stable rule identifier,
its optional description is the message, and items refer to KLayout category paths and qualified
cell names. A value such as `box: (0.1,0.2;0.3,0.4)` supplies the physical location. Nested
categories, cell-reference graphs, DTDs, entities, duplicate names, unknown references, multiple
boxes, XML attributes, and excessive XML complexity are rejected instead of being guessed.

### Netgen LVS

The text adapter recognizes an unambiguous terminal result (`Result: Circuits match uniquely.`,
`Netlists do not match.`, or the documented prefix-free/`LVS result` equivalents), property errors,
bounded unmatched net/device/pin counts, and explicit warning/error lines. A report that says
both match and mismatch is rejected.

### Magic PEX

The text profile recognizes `PEX status: complete`, a confined relative `Output:` path, bounded
`Devices:` and `Nets:` counts, and explicit warning/error lines. A completion mixed with an error
is rejected. The declared PEX artifact remains the content authority: the adapter never follows
an output path printed by a tool report.

## Exact, expiring waivers

A waiver contains the exact `finding_id` emitted by a reviewed report. The identity includes the
rule plus a full 256-bit SHA-256 fingerprint of the normalized producer version, message, source,
location, bounding box, and objects; it is not a short display hash. The waiver also retains redundant
human-readable `tool`, `rule`, `source`, optional `line`, normalized object set, `expires`, and a
reason. The ID binds the tool version, message, location, bounding box, and objects, so a changed
diagnostic cannot inherit an old waiver merely by remaining on the same source line. Empty objects
match only an empty object set; they are not a wildcard.
One waiver may match at most one finding, and one finding may match at most one waiver. Ambiguous
matches are input errors. Active matches retain their original severity and finding ID but are
excluded from the decision. Expired waivers do not weaken the gate and create `WAIVER.EXPIRED`;
unmatched active waivers create `WAIVER.UNUSED`. Completeness and lineage findings cannot be
waived, including a mismatch between Magic's reported PEX output and the content-bound artifact.

## Resource and trust boundaries

- strict JSON rejects duplicate keys, non-finite values, oversized numbers, excessive depth,
  and excessive node counts;
- portable paths reject absolute and drive paths, backslashes, `.`/`..`, Windows reserved names,
  alternate-data-stream or wildcard characters, trailing dots/spaces, non-NFC Unicode, missing
  files, non-files, and symlink escapes;
- normalized text fields reject Unicode controls, directional formatting, and line/paragraph
  separators so findings remain safe to render in terminals and CI logs;
- artifact, report, total-byte, line, line-length, finding, XML-node, XML-depth, and object limits
  are fixed in the runtime;
- report text must be UTF-8 without NUL bytes;
- no subprocess, simulator, shell, plug-in loader, environment expansion, or network API is used.

Run the clean-room fixture and emit schema-valid JSON:

```console
schematic-airlock verification-check tests/fixtures/verification_bundle --format json --pretty
```

Add `--output report.json` to write a file. Output is no-clobber by default and replacement
requires `--force`. The destination may never alias the manifest, an artifact, or a tool report,
even when forced. A same-directory temporary file is flushed and atomically installed so a failed
write cannot leave a partial report or damage evidence.

The default threshold returns exit code 2 for `review` or `deny`, and exit code 3 for malformed
input. `--fail-on deny` permits review findings without turning the process red.
