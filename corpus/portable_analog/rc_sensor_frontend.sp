* Clean-room passive sensor-front-end shaped example.
.param rsrc=2k cfilter=4.7n gain_load=20k

.subckt rc_section input output ground
.param r=1k c=1n
Rseries input output {r}
Cshunt output ground {c}
.ends rc_section

VSENSE sensor 0 0.25
Rsource sensor raw {rsrc}
Xfirst raw stage1 0 rc_section
Xsecond stage1 filtered 0 rc_section
Rload filtered 0
+ {gain_load}
.end
