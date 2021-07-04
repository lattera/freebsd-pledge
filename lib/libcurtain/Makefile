.include <src.opts.mk>

PACKAGE=	runtime
LIB=		curtain
MAN=

SRCS=		curtain.c pledge.c ioctls.c config.c pathexp.c utils.c auto.c tmpdir.c gui.c
INCS=		curtain.h pledge.h
CFLAGS+=	-I${.CURDIR}

CONFGROUPS=	BASECONF GUICONF
BASECONFDIR=	/etc
BASECONF=	curtain.conf
GUICONFDIR=	/etc/curtain.d/_gui.d
GUICONF=	fontconfig.conf
.if ${MK_EXAMPLES} != "no"
FILESDIR=	${SHAREDIR}/examples/curtain
FILES=		curtain.conf.sample
.endif

MKTABFILES=	sysfiltab.c privtab.c socklvltab.c sockaftab.c
CLEANFILES+=	$(MKTABFILES)
SRCS+=		$(MKTABFILES)
SYS_SYSFIL_H=	${SYSROOT:U${DESTDIR}}${INCLUDEDIR}/sys/sysfil.h
SYS_PRIV_H=	${SYSROOT:U${DESTDIR}}${INCLUDEDIR}/sys/priv.h
NETINET_IN=	${SYSROOT:U${DESTDIR}}${INCLUDEDIR}/netinet/in.h
SYS_SOCKET_H=	${SYSROOT:U${DESTDIR}}${INCLUDEDIR}/sys/socket.h
sysfiltab.c: mksysfiltab.awk ${SYS_SYSFIL_H}
	awk -f ${.CURDIR}/mksysfiltab.awk < ${SYS_SYSFIL_H} > ${.TARGET}
privtab.c: mkprivtab.awk ${SYS_PRIV_H}
	awk -f ${.CURDIR}/mkprivtab.awk < ${SYS_PRIV_H} > ${.TARGET}
socklvltab.c: mksocklvltab.awk ${NETINET_IN}
	awk -f ${.CURDIR}/mksocklvltab.awk < ${NETINET_IN} > ${.TARGET}
sockaftab.c: mksockaftab.awk ${SYS_SOCKET_H}
	awk -f ${.CURDIR}/mksockaftab.awk < ${SYS_SOCKET_H} > ${.TARGET}

.include <bsd.lib.mk>

