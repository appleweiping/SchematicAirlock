* Clean-room hierarchical OTA-shaped structural example.
.include primitives.lib
.global vdd 0
.param supply=1.8 bias=20u load=2p

.subckt bias_cell vdd vss vb
.param rbias=90k
Rset vdd vb {rbias}
Mdiode vb vb vss vss nch
.ends bias_cell

.subckt gain_cell vinp vinn vout vdd vss vb
.param rload=40k
Mleft nleft vinp ntail vss nch
Mright vout vinn ntail vss nch
Mtail ntail vb vss vss nch
Rleft vdd nleft {rload}
Rright vdd vout {rload}
.ends gain_cell

.subckt output_cell vin vout vdd vss
.param rout=10k
Mout vout vin vss vss nch
Rout vdd vout {rout}
.ends output_cell

VDD vdd 0 {supply}
VINP vinp 0 0
VINN vinn 0 0
Xbias vdd 0 vb bias_cell
Xgain vinp vinn nstage vdd 0 vb gain_cell
Xout nstage vout vdd 0 output_cell
Cload vout 0 {load}
.end
