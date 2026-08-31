* deliberately small static demonstration
.include models/basic_models.lib
VDD vdd 0 1.8
VINP vinp 0 0.9
VINN vinn 0 0.9
XCORE vinp vinn vout vdd 0 diff_core
RLOAD vdd vout 10k
.op
.end
