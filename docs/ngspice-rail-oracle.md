# ngspice 42 rail-intent oracle

This page records an independent simulator probe used to review the deliberately
narrow `RAIL002` proof profile. It is external evidence, not a runtime dependency,
a CI gate, or a claim that SchematicAirlock reproduces ngspice semantics.

## Provenance and execution

The Windows 64-bit console archive was downloaded over TLS from the official
[ngspice 42 release directory][release]. That page identifies
`ngspice-42_64.7z` as the 64-bit Windows console/GUI package and notes that the
file was remade. It did not provide an official checksum, so the hashes below
are locally recorded identities rather than vendor-authenticated checksums.

- archive SHA-256:
  `aa98b3c74743260a38835bd2698f58221b7237939798d1fdf2297f44ecf1d6ec`;
- `Spice64/bin/ngspice_con.exe` SHA-256:
  `f86062f3bb1016dcf1552a57f38954891b4e71aee6defbebde6de589ee55682f`;
- the binary reported `ngspice-42`, the KLU solver, and a creation date of
  2023-12-27;
- the initial task-scoped acquisition harness/report SHA-256 values were
  `a3d8b3c0b927619f4d9976e71d7ddccadcaf2a3d86adea2b35776861ac631262`
  and `ce3fa33431929eb862ca685aeff64370bfd923364eb9a7b06d22a180ae296bca`;
- the initial public replay used harness SHA-256
  `e48e177228cd53cb6cb7631e65d0566d2b83df15b30dfafbe2d7656f0c3187b9`;
- its retained [historical result](../benchmarks/results/ngspice-42-windows-rail-oracle-20260909.json)
  SHA-256 is
  `017d63bcb6fa985b97e5a352eae9f871a6434fa78ceb192a36b2ff81891e2bff`;
- the current independently replayed [bounded harness](../benchmarks/ngspice_rail_oracle.py)
  SHA-256 is `8593fd52d30aed6733756d6cd80078e3f339b5ff0ccc6c6d8d30ca0c6a4dfb21`;
- its de-identified [18-case result](../benchmarks/results/ngspice-42-windows-rail-oracle-20260909-v2.json)
  SHA-256 is `08468408dec8fd43dfd45fea2f4fb957fbcf7d710325d6b1a8109972b5c070d2`.

The second replay added a bounded, content-verified copy immediately before
each simulator invocation and rejection of final-component symlinks before
path resolution. It is a new execution of all 18 cases, not a rewrite of the
earlier report. Both reports retain the same deck and simulator identities and
the same expected numerical observations.

Each of 18 independent decks (nine rail boundaries and nine parameter-scope or
dependency boundaries) was executed without user init files as
`ngspice_con.exe -n -b -o CASE.log CASE.cir`. The harness refused an unexpected
archive, binary, deck hash, deck set, exit status, missing numeric observation,
or output larger than 1 MiB. The report binds every deck, log, stdout, and stderr
by SHA-256. The initial acquisition retained raw logs as task-scoped review
artifacts. The public replay harness instead uses a temporary directory that
is removed when it exits; it retains only bounded log identities and parsed
observations in the published JSON, not the raw replay logs. Log hashes identify
this specific observation and are not
expected to repeat because ngspice prints run time and host-memory data.

Replay requires the caller to provide the executable and its independently
obtained expected hash; the harness never downloads or discovers a simulator:

```console
python -I -S benchmarks/ngspice_rail_oracle.py \
  --ngspice PATH/TO/ngspice_con.exe \
  --expected-sha256 f86062f3bb1016dcf1552a57f38954891b4e71aee6defbebde6de589ee55682f \
  --archive PATH/TO/ngspice-42_64.7z \
  --expected-archive-sha256 aa98b3c74743260a38835bd2698f58221b7237939798d1fdf2297f44ecf1d6ec \
  --output rail-oracle.json
```

The runner refuses to overwrite an existing report. It constrains each process
to 30 seconds, each output file to 1 MiB, the executable to 64 MiB, the optional
archive to 128 MiB, and each immutable input deck to 4 KiB. Any timeout, output
overflow, hash/version mismatch, extra or missing deck, unexpected exit status,
or incomplete numeric observation fails the run.

The executable, optional archive, individual deck, and case-directory final
path component must not be a symlink. Parent-directory symlinks and Windows
junctions are resolved normally; this is an exact-content replay harness, not a
filesystem sandbox. A deck is read with a 4,097-byte bound and checked against
its inventory hash before creating the private copy, and that copy is hashed
again before execution. The executable and optional archive are hash-checked
before use. These checks do not claim race-proof isolation from a concurrent
process that can replace trusted executables or mutate the private work area.

## Observations

| Boundary | ngspice 42 result | Static-gate consequence |
|---|---|---|
| `R n 0 0`, driven by 1 A | reported 0.001 ohm and 1 mV | Treat `R=0` only as declared short intent, not exact simulator equality. |
| two series `R=0`, driven by 1 A | each reported 0.001 ohm; 2 mV total | A composite `R=0` finding remains an artifact-level declaration. |
| explicit `R=1m`, driven by 1 A | 1 mV | A nonzero milliohm value must not enter the proof. |
| plain positive ideal `L`, DC OP | 0 V | It may support the documented DC-only proof profile. |
| independent `V DC 0` | 0 V | A bare static literal zero source may support the profile. |
| `V PULSE(0 1 ...)` | 0 V at OP, 1 V transient maximum | OP zero does not prove a static source declaration; dynamic sources stay excluded. |
| `L ... Rser=1` | rejected as an unknown parameter | Dialect-specific modifiers cannot be guessed. |
| attempted positional inductor model plus modifier | rejected as an unknown parameter | Opaque positional fields stay outside the profile. |
| `L ... m=0` | accepted and 0 V at OP | Acceptance alone is not enough; any extra parameter remains conservatively excluded. |

The parameter cases separately establish the precedence observed in this exact
binary: instance assignment, subcircuit-body `.param`, subcircuit-header
default, then enclosing/global value. A dependent header or body expression was
re-evaluated with the winning instance assignment (`a=4`, `b={a+1}` produced
5 ohms), while a top-level dependent binding was recomputed after a later
same-scope override (`a=0; b={a}; a=1` produced 1 ohm). These observations bound
the final-binding regression oracle; they do not claim portability to every
SPICE dialect.

The current online [ngspice manual][manual] says that a zero resistor is replaced
with `1e-12` ohm. This particular official ngspice 42 Windows binary instead
reported `0.001` ohm under its default configuration. The discrepancy is exactly
why `RAIL002` documents a netlist-intent proof rather than promising a simulator's
regularization value.

This probe does not establish behavior for another ngspice build, another SPICE
dialect, compatibility mode, temperature/model combinations, nonlinear devices,
or analyses other than those explicitly listed. It is a false-positive oracle
for this bounded rule, not general electrical-safety evidence.

[release]: https://sourceforge.net/projects/ngspice/files/ng-spice-rework/old-releases/42/
[manual]: https://ngspice.sourceforge.io/docs/ngspice-manual.pdf
