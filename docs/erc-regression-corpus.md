# Electrical-rule regression corpus

The electrical-rule corpus is an original set of small SPICE artifacts whose
expected outcomes are declared in
[`tests/corpus/erc/manifest.json`](../tests/corpus/erc/manifest.json). Its purpose
is to make each boundary reviewable: every case states the physical reason for
the expected result, the exact finding identifiers or voltage-check statuses,
and whether it is a positive, negative, or indeterminate boundary.

The manifest and every referenced deck are test inputs, not trusted summaries.
`tests/test_erc_corpus.py` decodes the manifest with the same bounded strict JSON
loader used by runtime contracts, rejects undeclared fields and orphan decks,
runs each artifact through the public API, and compares the complete result.
The inventory gate also requires all 16 current electrical finding identifiers,
all recognized device families plus the deliberately unknown `Z` family, and
all five voltage-envelope result states to be exercised.

## What the cases establish

The audit cases distinguish definite defects from conservative review and safe
counterexamples:

- negative or unresolved passive values (`VAL001`, `VAL002`);
- excessive literal and unbounded dynamic sources (`VOLT001`, `VOLT002`);
- missing or undriven declared ports and suspicious internal nets
  (`PORT001`, `PORT002`, `NET001`, `NET002`);
- conflicting independent sources and ideal-source loops (`SRC001`,
  `SOLVE003`);
- missing references and DC-floating islands (`SOLVE001`, `SOLVE002`);
- behavioral and unknown device families (`ELEM002`, `ELEM001`); and
- direct and composite power-to-ground DC ties (`RAIL001`, `RAIL002`).

Hierarchy is not represented by a renamed flat surrogate. One case proves that
an instance parameter changes the expanded source voltage, while another keeps
an excessive source inside an unreachable subcircuit and separately checks the
unreachable-definition diagnostic. The primitive-family case includes R, C, L,
V, I, M, D, Q, E, G, F, H, and X devices in one grounded network.

The voltage cases exercise explicitly rated MOS and diode terminals, a definite
rating violation, a partially overlapping PVT envelope, an unknown resistive
drop, and contradictory nominal sources. They therefore preserve the semantic
difference between `pass`, `violation`, `possible-violation`, `indeterminate`,
and `inconsistent`.

## Declared DC rail-short paths

`RAIL001` remains the focused diagnostic for one literal zero-ohm resistor that
directly joins a configured power net to a configured ground net. `RAIL002`
covers a wider, still conservative netlist-intent statement: a connected path
made only of successfully evaluated zero-resistance declarations, static literal
zero-volt independent sources, and valid positive ideal inductors. The proof is
of this declared short-intent path, not a promise about a simulator's regularized
resistance values or a fabricated circuit's voltage difference. The independently
recorded [ngspice 42 rail-intent oracle](ngspice-rail-oracle.md) documents the
simulator boundary behind that wording.

No tolerance is applied. An explicitly nonzero 1 mΩ resistor is not a zero-resistance
declaration. Unknown or negative
inductance, a zero-valued inductor, parameterized or dynamic voltage sources,
nonzero voltage sources, capacitors, controlled sources, MOSFETs, diodes, and
BJTs are never guessed to be short-circuit evidence. The unit oracle also checks
these exclusions directly.

The proof profile requires bare R/L devices without additional model names,
positional modifiers or device parameters. Static V sources may only have the
literal or `DC literal` form, without extra parameters. Modifier interpretation
is not guessed: even a familiar `ic` or `m` field requires a separate validated
profile before it can support a proof. These restrictions also apply to RAIL001.
Node `0` always denotes SPICE ground and cannot be configured as a power rail.

Zero-ohm resistors are treated as ideal straps by this artifact contract. This
does not promise a simulator's internal numerical representation: ngspice, for
example, regularizes literal zero resistance to a small positive value. The
current online manual states 1e-12 Ω, while our separately logged ngspice 42
Windows oracle actually reports 1e-3 Ω under its default configuration. Neither
is represented as exactly zero simulator resistance by this gate. Ideal
positive inductors and literal zero-volt sources instead impose a zero DC
voltage difference directly. See the [ngspice manual](https://ngspice.sourceforge.io/docs/ngspice-manual.pdf),
resistor and inductor device sections.

### Numerical proof boundary

Numeric literals are independent of the calling thread's Decimal context and
never silently underflow to zero. They are limited to 1,024 characters/digits;
nonzero magnitudes must lie in `[1e-100, 1e100]`. Out-of-range inputs stay unknown
or produce an input finding instead of becoming short evidence. Fixed-point
formatting preserves the exact bounded Decimal without `normalize()` rounding.

The ordinary expression API retains a fixed 50-digit, half-even calculation
profile. Hierarchy expansion and parameter propagation explicitly use its
`exact=True` proof profile: up to 1,024 digits with an inexact-arithmetic trap.
Nonterminating division or a calculation exceeding that precision is unresolved,
not a rounded proof. Invalid parameter overrides discard an inherited value of
the same name; they cannot accidentally reuse an earlier zero. Expression text,
tokens, nesting and parameter counts are bounded separately. These finite-decimal
rules are not a general symbolic algebra engine or simulator expression language.

Source scopes merge their final declarations before evaluating dependencies.
For subcircuits the precedence is instance override, body `.param`, header
default, then inherited scope. Top-level final redefinitions also affect derived
parameters. Acyclic dependencies are resolved within a 128-name scope limit and
a one-million-attempt budget for the whole hierarchy. Unknown/cyclic dependencies
remain unresolved; even a later valid override cannot erase an earlier malformed
declaration diagnostic. The ordinary `parameter_assignments` utility remains a
left-to-right expression API, distinct from this source-scope resolver.

Voltage and passive-value checks use final reached bindings for parameterized
devices. They do not mistake an uninstantiated default for an instance's value.
Unused definitions retain literal artifact checks and their unreachable finding.

Composite-path evidence is deterministic and bounded. A finding records the
number and SHA-256 of every element in one shortest proof, but displays at most
12 bounded device names. This keeps a million-element adversarial path from
turning one diagnostic into an unbounded report. The digest is consistency
evidence for the reported proof, not an authenticity signature.

## Scope

These artifacts test SchematicAirlock's documented static contracts. They are
not copied simulator regression decks, a PDK rule deck, a transistor operating
point oracle, or evidence that every circuit accepted by the gate will simulate
or be safe to fabricate. Adding a new electrical finding family requires a new
manifest case with an independently explained positive or indeterminate
boundary and, where false positives are plausible, a negative counterexample.
