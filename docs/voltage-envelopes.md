# DC voltage envelopes and terminal ratings

`voltage-check` proves voltage-difference bounds from a netlist and explicit
operating-envelope assumptions. It does not run a simulator, solve MOS operating
points, infer transistor ratings from model names, or certify a design for fabrication.
Run the ordinary `audit` command as well: this command does not replace the
structural/executable-input safety gate.

```console
schematic-airlock voltage-check examples/voltage_envelope/design.sp --rules examples/voltage_envelope/rules.json --format json --pretty
```

The example is an original illustrative CMOS circuit. Its model ratings and
output envelope are **user assumptions**, not measurements, PDK data, or a solved
inverter transfer curve. The independent output/rail envelopes intentionally
permit a 0.36 V PMOS body-to-drain forward difference; the 0.3 V policy flags a
`possible-violation`. Narrowing or correlating the envelopes requires evidence,
not simply changing a rule to get a green report.

## What the constraints mean

For each constraint, `min <= V(positive) - V(negative) <= max`. All voltages are
exact rational numbers internally. Input rule endpoints are decimal strings in
volts (for example `"1.8"`); output endpoints are canonical fractions (`"9/5"`).
`null` means that no finite bound was proved. It never means zero or omitted data.

The adapter imposes only these relationships:

- A literal independent source (`V1 p n 1.8`, `DC 1.8`, or a finite SPICE-scaled
  literal) gives an exact difference. Only the original token is used, so
  arithmetic rounding in other structural checks cannot change the proof.
- A literal zero-ohm resistor joins two voltages exactly.
- `source_envelopes` replaces a named source's exact value with a supplied
  operating envelope. It must contain an existing literal DC value. It can also
  explicitly bound a source whose expression/waveform is otherwise unresolved.
- `net_envelopes` constrains an expanded node against node `0`. These are
  explicit assumptions; they are not an expected-value check or a simulation result.

Node `0` is the only inherent voltage reference. Names such as `vss` or `gnd`
are not silently tied to it. Source names are fully qualified (`top/v1`,
`top/xamp/vbias`); internal node names include their instance (`top/xamp:internal`).
Identity is case-insensitive at this adapter boundary. Ambiguous literal node
and device/subcircuit names containing `:` or `/` are rejected for voltage checking.
If Unicode case folding would merge two identities distinguished by the parser,
or produce a non-NFC identity, the adapter returns indeterminate rather than
merging or silently changing their electrical domains.

The original literal sources are independently checked for nominal contradictions
before scenario envelopes are applied. In addition, a variable ideal-source loop
remains indeterminate: an interval feasible set alone cannot prove compatibility
of every independently varied source combination. A broader envelope never hides
a nominal 5 V/6 V parallel-source conflict or silently chooses just the feasible
point of an independently varied parallel source.

Series supplies, floating domains and common-mode correlation are preserved.
If a floating source fixes `V(a)-V(b)=1`, the pairwise result is exactly 1 even
when both absolute node voltages are unbounded. Independent interval subtraction
would lose that fact and is not the algorithm used here.

## Rules and outcomes

An `expected` entry asserts an allowed voltage difference. Model ratings use the
exact parsed model identifier and an explicit kind; NMOS/PMOS polarity is never
guessed. Every MOS rating must specify six **signed** pairwise ranges: `gs`,
`gd`, `gb`, `ds`, `bs`, and `bd`. The first letter is the positive terminal. A
diode requires `ak`, so its lower/upper limits can describe reverse/forward bias.
Use device/foundry-approved limits for a real design.

| Result | Meaning |
| --- | --- |
| `pass` | Every requested range contains its proved envelope, with no unassessed notes |
| `violation` | A proved envelope is entirely outside its allowed range |
| `possible-violation` | A finite envelope overlaps the allowed range but extends outside it |
| `indeterminate` | Bounds, a rating, supported semantics, complete input, or work budget are missing |
| `inconsistent` | Ideal sources/envelopes contradict each other; no simultaneous voltage assignment exists |

Bounds are conservative over the stated ideal constraints. A possible violation
does not establish that a nonlinear operating point actually reaches the worst
case. Conversely, a `pass` is conditional on every stated assumption and applies
only to these voltage checks. Any non-pass result returns CLI exit 2; malformed
rules/references or invalid file operations return 3. JSON and text include
source locations, input digests, rule fingerprint, assumptions and work counters.
Output is atomic/no-clobber and may not alias any read input or rule file, even
with `--force`.

## Algorithm and verification

1. A weighted union-find eliminates exact voltage equalities, retaining signed
   offsets and detecting contradictory exact loops.
2. Interval inequalities form directed upper-bound edges. Bellman-Ford detects
   negative cycles or constructs feasible vertex potentials.
3. Reweighted sparse Dijkstra searches provide tight pairwise bounds. Forward
   and reverse searches preserve correlation; only one queried component's
   distances are cached, avoiding a quadratic all-pairs cache.

Arithmetic has a 4096-bit rational budget. Node/constraint/query/edge-visit
budgets are explicit. The last two are cumulative, including repeated queries;
exhaustion invalidates the system and clears any partial report checks. The
adapter also retains existing file/include/hierarchy bounds (100000 expanded
devices). A standalone constraint system has separate limits. Large exact-source
chains collapse to one component rather than requiring all-pairs storage.

Tests compare 180 seeded mixed-equality/interval graphs with an independent dense
Floyd-Warshall oracle, cover a 20000-source chain, reversed sources, floating
correlation, contradictions, subcircuit ports, all MOS pairs, diode polarity,
unknown states, narrow decimal precision, malformed rules, output aliasing and
display-control rejection. This is implemented evidence, not a claim that a
million-device netlist workload or foundry ERC coverage has already been accepted.

An original scalable kernel benchmark has a closed-form series-source oracle:

```console
python benchmarks/voltage_constraints.py --sources 100000 --repetitions 3
```

It records exact reconstruction, source/harness hashes, elapsed time and peak
Python allocations measured with `tracemalloc` (not total process RSS). This
kernel measurement excludes netlist parsing, hierarchy expansion and nonlinear
checks; it does not replace the separate million-device end-to-end acceptance.
The [2026-09-09 measured record](../benchmarks/voltage-kernel-20260909.json)
contains one run each at 100000 and 1000000 sources: 22.0 s / 71.2 MB and
264.3 s / 657.3 MB traced Python allocations, respectively, on a shared Windows
host with tracing enabled. Both matched the exact closed-form voltage. These
are informational single-run observations, not throughput guarantees.

## Current unassessed semantics

Nonzero resistors, capacitor/current-source branches, MOS channels and diodes do
not invent voltage ties. An unloaded divider's numeric operating point is not
computed. Nonliteral/negative resistance remains unassessed even if an existing
expression evaluator happens to round it to zero. Nonliteral source expressions
need explicit envelopes; there is no
transient waveform simulation. Controlled sources, inductors, BJT behavior,
global/sweep/conditional directives and unmatched voltage models keep the report
indeterminate. Min/max transistor conduction propagation, leakage-current
analysis and real-PDK false-positive/negative studies remain separate work.

The packaged Draft 2020-12 schemas describe JSON shape. Runtime validation also
enforces exact finite bounds, ordered ranges, normalized/collision-free names,
NFC and display-control restrictions, known references and resource limits.
