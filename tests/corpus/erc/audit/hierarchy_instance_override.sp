* The reached instance overrides a safe default with an excessive source value.
XHOT vdd 0 rail_cell params: level=30
RLOAD vdd 0 2k
.subckt rail_cell positive negative params: level=1
VCORE positive negative {level}
.ends rail_cell
.end
