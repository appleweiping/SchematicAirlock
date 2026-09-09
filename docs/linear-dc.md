# Exact linear DC operating points

`linear-dc` computes an independently verified operating point for the closed
`linear-rvi-v1` profile. It supports nonnegative literal resistors, independent
DC voltage/current sources and parameter-free hierarchy. This is separate from
`audit` and `voltage-check`: a solved operating point does not relax an artifact
safety decision or establish nonlinear transistor behavior.

```console
schematic-airlock linear-dc examples/linear_dc/divider.sp --format json --pretty
```

The example yields exactly `V(out) = 3`, `I(top/r1) = 1/1000` and
`I(top/v1) = -1/1000` in volts and amperes. Positive current flows from the
first terminal to the second; positive `absorbed_watts` is dissipated/absorbed
power, so a delivering voltage source has negative power. Ground is only node
`0`; a name such as `gnd` is not implicitly grounded.

## Mathematical and resource contract

The kernel constructs modified nodal equations from Kirchhoff's current law,
Ohm's law and ideal voltage constraints. Each ideal voltage source, including
a zero-ohm resistor, introduces its branch current as an unknown. Exact rational
sparse Gaussian elimination uses deterministic row pivots and indexed column
membership. No artificial `gmin`, arbitrary ground, least-squares fit or numeric
tolerance repairs a singular network. A second pass through the original
branches verifies ideal voltage differences, every node's current balance
(including ground) and the total power balance before returning any solution.

The API uses `Fraction` in SI units. It is exact for the stated linear ideal
model, not for real devices. Sparse fill, cumulative operations, node/branch/
unknown counts, input-name bytes and 4096-bit numerator/denominator sizes are
bounded. Defaults are 50,000 nodes, 100,000 branches and unknowns, one million
stored matrix coefficients, 20 million counted operations and 16 MiB of input
names. Index overhead and process memory are not mislabeled as matrix nonzeros.
The netlist adapter additionally retains the existing bundle/include limits
and caps expanded hierarchy at 100,000 entries. These limits are ceilings, not
a claim that every graph at the ceiling fits its fill or operation budget.
In-memory netlists are preflighted at two million UTF-8 bytes; source metadata
must fit the display-safe 1024-character path profile. A conservative 64-MiB
serialization-size budget is checked before creating the parallel JSON wire
tree or the text report. This is an output bound, not a total-process RSS claim.

```python
from fractions import Fraction as F
from schematic_airlock import DCBranch, solve_linear_dc

solution = solve_linear_dc(
    [
        DCBranch("injection", "current", "0", "out", F(1, 1000)),
        DCBranch("load", "resistor", "out", "0", F(3000)),
    ]
)
assert dict(solution.voltages)["out"] == F(3)
```

Kernel names are exact and case-sensitive. The netlist adapter accepts a closed
ASCII token grammar, normalizes SPICE case, rejects literal hierarchy separators
and retains source file/line locations. Instance-local internal nets stay distinct.
Input bytes and the canonical branch network have separate digests. A digest
provides consistency, not publisher authentication.

## Failures and unsupported semantics

| Status | Meaning |
| --- | --- |
| `solved` | All unique node voltages/currents found; exact physical residuals are zero |
| `inconsistent` | Ideal equations have no simultaneous solution |
| `singular` | Voltages or ideal-source currents are not uniquely determined |
| `unsupported` | Parsing, naming, devices, parameters or directives are unassessed |
| `budget-exceeded` | A complete proof did not fit the configured bounds |

Failure reports contain no partial electrical values. Identical parallel
voltage sources are singular even if their voltage is determined, because the
individual source currents are not. Unequal parallel ideal sources are inconsistent.
The packaged [JSON report schema](schemas/linear-dc-report-v1.schema.json)
describes that shape, including empty electrical fields for every failure status.
Runtime checks additionally enforce exact rational arithmetic and physical residuals.

The literal parser reads the original source token, never a rounded expanded
expression. It accepts finite decimal/SPICE-scaled literals with an appropriate
optional ASCII unit suffix. Electrical identifiers and values must be bare
tokens: single- and double-quoted tokens are rejected rather than reinterpreted
after quote removal. Quoted include paths and title text remain valid.
Expressions, negative resistance, device parameters,
temperature coefficients, PULSE/PWL/AC sources, capacitor/inductor operating-point
approximations, MOS/diode models, controlled sources, `.global`, `.param`, `.lib`
sections and subcircuit-local directives are deliberately rejected. Only bare
`.op`, final entry-file `.end`, `.title` and top-level confined `.include` cards
are admitted. Content following `.end` is not silently solved. Parameter-free
`.subckt`/`.ends` and `X` calls are supported; unresolved calls never become wires.

CLI exit 0 means `solved`, exit 2 means a completed non-solved assessment, and
exit 3 means malformed CLI/filesystem input or output failure. Reports use the
existing atomic/no-clobber writer; even `--force` may not overwrite a read input.

Tests include exact divider and supernode oracles, 80 prescribed-voltage random
resistor meshes with independently derived current injections, a sparse 300-link
chain, singular/inconsistent networks, current/power sign conventions, budget
failure, malformed netlists, hierarchy and confined/atomic CLI behavior.

The opt-in integration harness runs only its own four fixed original decks in
temporary directories, with real ngspice and user/system startup files disabled:

```console
python benchmarks/linear_dc_ngspice.py --ngspice ngspice
```

It requires exactly one complete finite output row and the requested probe names,
compares ten node voltages against exact results with `1e-11 V + 1e-11 * abs(V)`
tolerance, and records simulator/executable, kernel, adapter, harness, deck and
result hashes. The four cases are a divider, a floating voltage-source supernode,
a loaded resistor bridge and two supplies plus current injection. These small
linear cases do not validate transistor models or nonlinear ERC coverage.

The [integration and boundary audit](linear-dc-integration-audit.md) records the
actual executable/implementation/output identities and adversarial regressions.
