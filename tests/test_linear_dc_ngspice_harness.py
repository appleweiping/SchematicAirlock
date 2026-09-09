from __future__ import annotations

import runpy
from fractions import Fraction

import pytest


def test_real_oracle_table_requires_exact_probe_set_and_one_complete_finite_row() -> None:
    check = runpy.run_path("benchmarks/linear_dc_ngspice.py")["check_table"]
    expected = {"out": Fraction(3)}
    assert check("out v(out)\n3 3\n", ("out",), expected) == 0
    for malformed in (
        "",
        "out v(out)\n",
        "out v(out)\n3 3\n3 3\n",
        "out v(other)\n3 3\n",
        "out v(out)\n3\n",
        "out v(out)\n3 nan\n",
        "out v(out)\ninf 3\n",
        "out v(out)\n3 0\n",
    ):
        with pytest.raises(AssertionError):
            check(malformed, ("out",), expected)
