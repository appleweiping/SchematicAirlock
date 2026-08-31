V1 vdd 0 3
V2 vdd 0 5
R0 vdd 0 0
M1 out gate 0 0 nch
C1 gate 0 1p
B1 out 0 V={V(gate)*2}
.tran 1f 1
.control
shell never-run
.endc
.end
