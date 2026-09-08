* Original minimal fixture: no foundry model or external netlist content.
.subckt demo_core vin vout vdd 0
RBIAS vdd vout 12k
CLOAD vout 0 3p
.ends demo_core
