# End-to-end hierarchy scaling

`benchmarks/hierarchy_scale.py` measures the complete public `audit_path`
pipeline on one compact, deterministic SPICE hierarchy. It includes confined
file loading, parsing, hierarchy-cost calculation, actual flattened-device
materialization, and every built-in structural and electrical rule. This is
different from a kernel-only counter or a source file containing millions of
repeated lines.

## Workload and independent oracle

The generated deck has one top-level voltage source and one root subcircuit
call. Each non-leaf definition contains `fanout` calls to the next definition;
the leaf contains `leaf_primitives` resistors. With fanout `f`, call depth `d`,
and `r` leaf resistors, the independent closed forms are:

- resistors: `r * f ** (d - 1)`;
- subcircuit calls: `sum(f ** k for k in range(d))`;
- expanded entries: resistors + calls + one source.

The canonical profiles use `f = 10` and `r = 10`:

| Depth | Resistors | Calls | Source | Total expanded entries |
| ---: | ---: | ---: | ---: | ---: |
| 4 | 10,000 | 1,111 | 1 | 11,112 |
| 5 | 100,000 | 11,111 | 1 | 111,112 |
| 6 | 1,000,000 | 111,111 | 1 | 1,111,112 |

The depth-6 source is fewer than 2,000 UTF-8 bytes and contains only ten
resistor statements and 51 call statements. Scale therefore comes from real
hierarchical expansion. The worker transparently wraps the production graph
builder used by `audit_path`, delegates to it exactly once, and records the
length and primitive families of the immutable expanded graph passed to the
rules. It fails unless those materialized R/V/X counts and the audit's file,
byte, static device, net, subcircuit, expansion-estimate, family, finding,
decision, and policy facts all match the separately calculated oracle. Reported
audit time and peak RSS include this additional linear `Counter` scan.

## Safe execution

Run the smaller profiles before attempting the million-resistor profile:

```console
uv run --frozen python -I benchmarks/hierarchy_scale.py --depth 4
uv run --frozen python -I benchmarks/hierarchy_scale.py --depth 5
uv run --frozen python -I benchmarks/hierarchy_scale.py --depth 6
```

The public process always starts a dedicated worker. On Windows it reads the
worker's operating-system `PeakWorkingSetSize`; on Linux it reads `/proc`'s
`VmHWM`. These are whole-process resident-memory measurements, not Python-only
`tracemalloc` values. The harness starts the base interpreter directly and adds
the active environment's site-packages explicitly, avoiding a Windows virtual-
environment redirector whose PID would measure only a waiting launcher. A 10 ms
monitor terminates the worker when its recorded peak reaches the configured
limit or when wall time reaches the timeout.
Limits may be lowered but cannot exceed 3 GiB or 180 seconds:

```console
uv run --frozen python -I benchmarks/hierarchy_scale.py --depth 5 --rss-limit-mib 2048 --timeout-seconds 120
```

Failure to read the live worker's OS memory counter is also fatal. The hidden
worker mode requires a per-run parent token so the documented interface cannot
accidentally bypass monitoring. Benchmark output is one JSON document. It binds
the imported Python source tree, harness, generated deck, bundle, and policy by
SHA-256 and reports both audit time and externally monitored worker wall time.
Timing is diagnostic and is comparable only on the same machine, interpreter,
checkout, power mode, and otherwise idle host.

## Historical v0.6 Windows run

The following profiles were run sequentially on the same Windows host on
2026-09-09. Background CPU load was not instrumented, so these measurements
are observations rather than performance guarantees or cross-machine
comparisons. Each linked JSON document preserves the exact harness, imported
source tree, generated deck, bundle, and policy hashes together with the
platform, Python executable, audit duration, monitored worker wall time, peak
resident memory, closed-form oracle, and independently observed materialized
device counts.

| Profile | Actual materialized R / X / V | Audit time | Worker wall time | Peak resident memory | Evidence |
| ---: | ---: | ---: | ---: | ---: | --- |
| depth 4 | 10,000 / 1,111 / 1 | 263.5692 ms | 1.062 s | 31.45 MiB | [JSON](../benchmarks/results/hierarchy-scale-windows-20260909-depth4.json) |
| depth 5 | 100,000 / 11,111 / 1 | 3,371.7901 ms | 4.546 s | 83.67 MiB | [JSON](../benchmarks/results/hierarchy-scale-windows-20260909-depth5.json) |
| depth 6 | 1,000,000 / 111,111 / 1 | 29,275.8642 ms | 30.187 s | 606.50 MiB | [JSON](../benchmarks/results/hierarchy-scale-windows-20260909-depth6.json) |

All three runs returned `allow` with zero findings and passed every recorded
closed-form and materialization oracle. That result applies only to the
synthetic profile described above; elapsed time and memory are not release
thresholds.

These historical observations bind tool version `0.6.0` and imported source-tree
SHA-256 `31ffb42633b8b39b54271038b080929cdb4cd529bb9e98d8f2cfd5428fbefb69`.
They are retained unchanged rather than relabeled as measurements of a later
version.

## Source-bound v0.7 Windows run

The same three profiles were rerun sequentially on 2026-09-09 with CPython
3.11.2 and tool version `0.7.0`. Each new result binds imported source-tree
SHA-256 `e3058f08dcaf4d3b97ff6c7e0f584b5c987545faf287a4a88ab28766db546e18`
and the unchanged harness SHA-256
`a435b2d01ba3a74dc91545532a5a70e62d2b9695f53a1179a3ec0f942aedff4b`.
The full final-parameter-binding and passive-value checks therefore ran over
the actually materialized instances; these are not reuses of the historical
timings.

| Profile | Actual materialized R / X / V | Audit time | Worker wall time | Peak resident memory | Evidence |
| ---: | ---: | ---: | ---: | ---: | --- |
| depth 4 | 10,000 / 1,111 / 1 | 922.8920 ms | 2.875 s | 30.38 MiB | [JSON](../benchmarks/results/hierarchy-scale-windows-20260909-v070-depth4.json) |
| depth 5 | 100,000 / 11,111 / 1 | 14,515.4067 ms | 16.469 s | 82.49 MiB | [JSON](../benchmarks/results/hierarchy-scale-windows-20260909-v070-depth5.json) |
| depth 6 | 1,000,000 / 111,111 / 1 | 91,110.9050 ms | 92.828 s | 605.39 MiB | [JSON](../benchmarks/results/hierarchy-scale-windows-20260909-v070-depth6.json) |

All three runs returned `allow`, zero findings, and exact agreement between the
closed-form counts and the graph supplied to the rules. They completed within
the unchanged 3 GiB resident-memory and 180-second wall-time guards. Other work
was active on the host and background CPU load was not instrumented. The
recorded times are higher than the historical observations, but these runs do
not isolate the cause or establish a speedup or regression attributable to the
implementation alone. The million-resistor profile still connects its repeated
devices to only two expanded electrical nets; it is not a million-node graph.

## Scope of the result

A successful depth-6 run proves that this checkout completed `audit_path` and
all current rules over this particular parallel, grounded, resistor hierarchy
under the recorded policy. It does not establish performance for arbitrary
million-node graphs, broad analog device mixes, deep or irregular hierarchies,
nonlinear simulation, PDK-aware ERC, or foundry sign-off. A small R/C/M test
guards mixed-family traversal semantics separately; it is not presented as a
large mixed-device benchmark.
