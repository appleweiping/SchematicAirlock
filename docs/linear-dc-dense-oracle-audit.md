# Linear DC dense-oracle audit

On 2026-09-08, the sparse exact linear-DC kernel was checked against the
independently assembled dense Fraction oracle in
`tests/test_linear_dc_dense_oracle.py`. The oracle uses full Gauss-Jordan
elimination and does not import production matrix, stamping, output, or
verification helpers.

The reproducible extended run used Python 3.11.2, seed `20731`, and 10,000
small mixed networks containing positive and zero-ohm resistors, independent
voltage and current sources, self-branches, grounded and floating components,
and fractional positive, zero, and negative source values. Results were:

- 3,421 unique systems,
- 2,013 singular systems,
- 4,566 inconsistent systems, and
- zero classification, voltage, branch-current, absorbed-power, or input-order
  mismatches.

The audited kernel SHA-256 was
`ac6fbb16e7030fb230d149555097598d89f2f34bb49ffe31892798a04916f6f8` and
the audited test source SHA-256 was
`cb0abf4039ec369448c71cc4a88c5aecf6b3d4202b8b207e1f6aaa16497e04c8`.
Run `uv run --frozen python tests/test_linear_dc_dense_oracle.py` to repeat the
10,000-case check. Normal CI runs the same generator and oracle for 500 cases.

This evidence is bounded to the kernel's ideal linear R/V/I profile. It does
not validate netlist parsing, nonlinear or reactive devices, simulator parity,
or performance at configured ceilings.
