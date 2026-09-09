* Original voltage-envelope example; these are illustrative, not foundry ratings.
VRAIL rail 0 1.8
VINPUT input 0 0.9
MN output input 0 0 nch
MP output input rail rail pch
.model nch NMOS (LEVEL=1 VTO=0.4 KP=100u)
.model pch PMOS (LEVEL=1 VTO=-0.4 KP=50u)
.op
.end
