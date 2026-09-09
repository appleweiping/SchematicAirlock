# Architecture

## Purpose

SchematicAirlock turns a local, untrusted SPICE artifact into a deterministic
decision before any simulator sees it. The implementation is separated into
small phases so every finding can point back to immutable source evidence.

## Data flow

1. `policy` validates a strict policy and produces its canonical fingerprint.
2. `bundle` establishes a filesystem root, entry file, and byte/file budgets.
3. `include_graph` reads and parses only safely resolved references.
4. `lex` joins continuation lines and records one-based source locations.
5. `parse` creates a bounded deck AST without evaluating simulator code.
6. `circuit_graph` constructs scoped nets, hierarchy calls, and an expansion
   upper bound without flattening the full design.
7. `checks` derives findings from load issues, syntax, topology, manifest
   intent, analysis budgets, and literal electrical values.
8. `engine` applies severity overrides, computes the decision and risk score,
   and freezes statistics and fingerprints into an `AuditReport`.
9. `report` and `cli` render that same report for humans or automation.

No stage invokes external programs. No later stage reopens files by absolute
path; it consumes bundle-relative names and immutable parsed objects.

## Trust boundaries

### Filesystem confinement

The canonical bundle root is resolved once. Every entry and include is resolved
with the filesystem and must remain below that root. Both POSIX and Windows
absolute path shapes are rejected. A symlink whose target leaves the root fails
the same containment check. Only regular files are accepted.

Read budgets apply before decoding. NUL-containing and non-UTF-8 files fail.
The bundle stores each successfully read file exactly once, preventing include
fan-out from multiplying byte accounting. Depth remains a property of each
active traversal path, so the parse cache cannot hide a deeper reference.
Top-level parameter directives are also recorded as a depth-first textual
event stream. Unique includes expand at their statement location rather than
in filename order. A repeated include emits `INCL003` and is not traversed
again: repeating a small include DAG must not expand evidence exponentially.
Its parameter events are not replayed and simulator-specific repeat semantics
are not claimed. The exact-DC and voltage-envelope adapters reject that include
issue instead of publishing a successful electrical result from partial events.

### Language confinement

Lexing understands comments, quoted tokens, braced expressions as opaque
tokens, and SPICE continuation lines. Parsing recognizes enough terminal
structure to build a useful graph. Unknown primitives remain visible as
reviewable elements; they are never executed.

Literal numeric handling uses `Decimal` and a small SPICE suffix table. The
expression helper implements only names, finite numbers, parentheses, and the
four arithmetic operators under token, depth, and magnitude limits. It never
uses Python `eval` or dynamic import.

### Resource confinement

Policy caps files, bytes, include depth, estimated hierarchy expansion,
analysis points, `.step` multipliers, and PWL points. Hierarchy cost is computed
recursively with a memo and saturates above the limit instead of fully expanding a large graph.
Recursion is reported and also saturates the estimate.

## Scope model

Top-level nets belong to the `top` scope. Each subcircuit definition owns a
`subckt:<lowercase-name>` scope. Endpoint records bind a qualified device name,
terminal role, and element family to one scoped net. A separate bounded
electrical expansion binds each `X` instance's parent terminals to child formal
ports, applies `.subckt` defaults and `params:` overrides, and namespaces
internal nets. Rail-short and ideal-source checks therefore cross hierarchy
without conflating separate calls. `X` calls count toward the expansion budget.

The voltage checker evaluates the supported finite parameter-expression
subset. Literal PULSE and PWL levels are checked against policy; unsupported
dynamic waveforms produce review findings rather than being silently allowed.

The manifest declares top-level intent separately. Its port roles do not modify
the graph. Checks compare intent with observed top-level net names and terminal
roles, preserving the distinction between submitted data and derived facts.

## Decision semantics

Each finding starts with `info`, `review`, or `deny`. A policy may override a
specific finding code after the check creates it. The final decision is the
greatest resulting severity: no findings or only info yields `allow`, any
review yields `review`, and any deny yields `deny`.

The risk score is a bounded prioritization aid, not a calibrated probability.
Weights accumulate per code with a cap, then the report caps the total at 100.
CI should gate on `decision`, never on undocumented score ranges.

## Determinism

Directory entries, include edges, decks, devices, nets, findings, metadata, and
digests are sorted before serialization. File hashes cover raw bytes. The
bundle hash covers relative path, size, and file hash for every read file. The
policy hash covers a canonical compact JSON encoding of validated policy data.

Reports intentionally omit wall-clock time, host name, working directory
except for the informational root field, random IDs, and simulator versions.
Finding IDs hash only stable finding content and source location.

## Failure model

An invalid root, entry, manifest, or policy is an input error because no audit
contract can be established. A failure found while following an include is a
denied finding so all reachable faults can be reported in one pass. A syntax
failure prevents graph facts from that file but does not execute recovery
heuristics that might invent connectivity.

## Extension rules

A new check should:

1. consume only `CheckContext` facts;
2. have a stable uppercase code and explicit default severity;
3. include actionable remediation for review and deny results;
4. be deterministic under source file enumeration order;
5. include a positive, negative, boundary, and severity-override test;
6. document any false-positive domain in the README;
7. avoid treating an unsupported expression as a proven numeric fact.

New parser support must preserve all resource bounds and source locations.
Features that require executing a model, resolving an ambient library, or
guessing dialect-specific behavior belong outside this process boundary.

Structural summaries from other tools remain untrusted input. The interop adapter enforces strict
JSON, confined portable paths, content digests, and a fresh local audit before comparing shared
counts. A comparison cannot lower an audit decision.
