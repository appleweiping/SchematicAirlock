* Safe bounded reference covering every recognized primitive family.
VBIAS rail 0 1.2
RUP rail sense 2k
RDOWN sense 0 3k
CSTAB sense 0 2p
LFEED rail aux 1n
RAUX aux 0 4k
IHELP rail 0 1u
MCORE rail gate 0 0 nch
RGATE gate 0 1meg
DCLAMP sense 0 diode
QBUF rail gate 0 npn
ECTRL eout 0 sense 0 1
GCTRL gout 0 sense 0 1m
FCTRL fout 0 VBIAS 1
HCTRL hout 0 VBIAS 1
RPAIR1 eout gout 1k
RPAIR2 gout 0 1k
RPAIR3 fout hout 1k
RPAIR4 hout 0 1k
XLOAD sense 0 load_cell
.subckt load_cell positive negative
RLOCAL positive negative 5k
.ends load_cell
.op
.end
