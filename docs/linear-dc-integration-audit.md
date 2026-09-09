# Linear DC executable and boundary audit

The 0.6.0 candidate was checked on 2026-09-09 against an actual ngspice 42
executable, not a replayed output fixture. The command was:

```console
PYTHONPATH=src python3 benchmarks/linear_dc_ngspice.py --ngspice /usr/bin/ngspice
```

The fixed original cases exercised a resistor divider, a floating voltage-source
supernode, a loaded resistor bridge, and two supplies plus a current source.
All ten node probes passed `1e-11 V + 1e-11 * abs(V)` tolerance. In this run,
the maximum absolute difference from the binary64 conversion of each exact
rational answer was zero. This does not assert exact arithmetic inside ngspice.

| Evidence | SHA-256 |
| --- | --- |
| ngspice 42 executable | `820658317b0b54035208da41936fd6871ce924036e5ea4113a4168b821b7fc45` |
| Exact DC kernel | `ac6fbb16e7030fb230d149555097598d89f2f34bb49ffe31892798a04916f6f8` |
| Netlist adapter | `8b8a25cce7f0f3def2adea76dd7256a689720271501ec50ccda8910cc300d16a` |
| Integration harness | `92ba21ccbea8a21a32d455a5ede26c3108a8ec83e5427d8d9304aa91406b31df` |
| Divider output | `28d083096656fa2c982dcfb25c9119faf0d280368e2e74df41bfee6fa3388adb` |
| Floating-source output | `8d58ec522ccf508a6cd684467c4e2e2785dbae25f74da3e8529a24f6bd5c6afb` |
| Bridge output | `f65a72e18a542ff182e94df7d1644c9a290b5261609de0569af282e772d79768` |
| Two-supply output | `8e04bf0cc402e64c75ca3461f2331b2bce501a16d0002ce878276b7344472a2c` |

The executable ran under Ubuntu/WSL with its startup files disabled (`-n`). The
harness validates finite values, complete probe columns, a single output row,
and an output byte limit. It prints deck, network, implementation, executable,
and output identities on each run; hashes identify this run, not every ngspice
build. The independent [dense arithmetic oracle](linear-dc-dense-oracle-audit.md)
checks a broader 10,000-network kernel corpus separately.

Boundary review reproduced and fixed four input classes before release:

- A depth-16 duplicated include chain previously produced 131,070 edges from
  33 include/source lines. Traversal now records 32 edges and 16 repeat
  diagnostics, without hiding an active include cycle.
- A flat list of 200 resistors previously materialized all 200 even with an
  expansion cap of one. The check now precedes each allocation; flat, nested,
  and sibling cases have parameterized regression tests at caps 1, 3 and 17.
- Empty/parameter-only subcircuit names and empty quoted element names now
  produce typed syntax diagnostics instead of raw indexing exceptions.
- Unicode-confusable scales and quoted electrical tokens are rejected before
  they can silently acquire bare-ASCII literal semantics. Quoted include paths,
  title text, and comments remain supported.

Repeated include diagnostics are linear in admitted input and remain subject
to existing file/byte/line bounds. They are not a constant-memory stream. These
experiments do not establish nonlinear transistor coverage, reactive-device
operating points, a million-device capacity result, or a general SPICE parser.
