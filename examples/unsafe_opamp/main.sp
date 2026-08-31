* this artifact exists to demonstrate several independent denials
VHI vdd 0 5
VCONFLICT vdd 0 3.3
RSHORT vdd 0 0
M1 vout floating_gate 0 0 nch
C1 floating_gate 0 1p
XLOOP vout recursive_cell
.subckt recursive_cell p
XAGAIN p recursive_cell
.ends recursive_cell
.tran 1f 10
.control
shell forbidden-command
.endc
.end
