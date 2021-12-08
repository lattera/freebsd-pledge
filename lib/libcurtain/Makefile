.include <src.opts.mk>

PACKAGE=	runtime
LIB=		curtain
MAN=

SRCS=		slot.c pledge.c ioctls.c config.c pathexp.c utils.c auto.c tmpdir.c gui.c
INCS=		curtain.h pledge.h
CFLAGS+=	-I${.CURDIR}

CONFGROUPS=	DEFCONF LOCCONF GUICONF
DEFCONF=	curtain.conf.defaults
DEFCONFDIR=	/etc/defaults
DEFCONFNAME=	curtain.conf
LOCCONF=	curtain.conf.local
LOCCONFDIR=	/etc
LOCCONFNAME=	curtain.conf
GUICONF=	fontconfig.conf
GUICONFDIR=	/etc/curtain.d/_gui.d
.if ${MK_EXAMPLES} != "no"
FILESDIR=	${SHAREDIR}/examples/curtain
FILES=		curtain.conf.sample make-drm-render-conf.c firefox-profile1.desktop
.endif

MKTABFILES=	abilitytab.c privtab.c socklvltab.c sockaftab.c
CLEANFILES+=	$(MKTABFILES)
SRCS+=		$(MKTABFILES)
SYS_ABILITY_H=	${SYSROOT:U${DESTDIR}}${INCLUDEDIR}/sys/curtain_ability.h
SYS_PRIV_H=	${SYSROOT:U${DESTDIR}}${INCLUDEDIR}/sys/priv.h
NETINET_IN=	${SYSROOT:U${DESTDIR}}${INCLUDEDIR}/netinet/in.h
SYS_SOCKET_H=	${SYSROOT:U${DESTDIR}}${INCLUDEDIR}/sys/socket.h
abilitytab.c: mkabilitytab.awk ${SYS_ABILITY_H}
	unifdef -U _KERNEL ${SYS_ABILITY_H} | awk -f ${.CURDIR}/mkabilitytab.awk > ${.TARGET}
privtab.c: mkprivtab.awk ${SYS_PRIV_H}
	awk -f ${.CURDIR}/mkprivtab.awk < ${SYS_PRIV_H} > ${.TARGET}
socklvltab.c: mksocklvltab.awk ${NETINET_IN}
	awk -f ${.CURDIR}/mksocklvltab.awk < ${NETINET_IN} > ${.TARGET}
sockaftab.c: mksockaftab.awk ${SYS_SOCKET_H}
	awk -f ${.CURDIR}/mksockaftab.awk < ${SYS_SOCKET_H} > ${.TARGET}

.include <bsd.lib.mk>

